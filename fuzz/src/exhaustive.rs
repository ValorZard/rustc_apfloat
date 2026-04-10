use std::io::Write;
use std::mem;
use std::num::NonZeroUsize;

use rustc_apfloat::FloatConvert;
use rustc_apfloat::ieee::Double;
use rustc_apfloat::ieee::Single;

use crate::Args;
use crate::Commands;
use crate::FloatRepr;
use crate::apf_fuzz::FuzzOp;

pub fn run_exhaustive<F: FloatRepr>(cli_args: &Args) -> Result<(), std::num::NonZero<usize>>
where
    F: Send + 'static,
    Single: FloatConvert<F::RustcApFloat>,
    Double: FloatConvert<F::RustcApFloat>,
{
    let Some(Commands::Bruteforce {
        min_width,
        max_width,
        verbose,
        only_non_trivial_fma,
    }) = cli_args.command
    else {
        unreachable!("bruteforce({cli_args:?}): subcommand not `Commands::Bruteforce`");
    };

    if !(min_width..=max_width).contains(&F::BIT_WIDTH) {
        return Ok(());
    }

    // HACK(eddyb) there is a good chance C++ will also fail, so avoid the
    // (more fatal) C++ assertion failure, via `print_op_and_eval_outputs`.
    let cli_args_plus_ignore_cxx = Args {
        ignore_cxx: true,
        ..cli_args.clone()
    };

    let all_ops = (0..)
        .map(FuzzOp::from_tag)
        .take_while(|op| op.is_some())
        .map(|op| op.unwrap())
        .filter(move |op| {
            if only_non_trivial_fma {
                matches!(op, FuzzOp::MulAdd(..))
            } else {
                true
            }
        });

    let op_to_combined_input_bits_range = move |op: FuzzOp<()>| {
        let mut total_bit_width = 0;
        op.map(|()| total_bit_width += F::BIT_WIDTH);

        // HACK(eddyb) the highest `F::BIT_WIDTH` bits are the last input,
        // i.e. the addend for FMA (see also `Commands::Bruteforce` docs).
        let start_combined_input_bits = if only_non_trivial_fma {
            1 << (total_bit_width - F::BIT_WIDTH)
        } else {
            0
        };

        start_combined_input_bits..u128::checked_shl(1, total_bit_width as u32).unwrap()
    };
    let op_to_exhaustive_cases = move |op: FuzzOp<()>| {
        op_to_combined_input_bits_range(op).map(move |i| -> FuzzOp<F> {
            let mut combined_input_bits = i;
            let op_with_inputs = op.map(|()| {
                let x = combined_input_bits & ((1 << F::BIT_WIDTH) - 1);
                combined_input_bits >>= F::BIT_WIDTH;
                F::from_bits_u128(x)
            });
            assert_eq!(combined_input_bits, 0);
            op_with_inputs
        })
    };

    let num_total_cases = all_ops
        .clone()
        .map(|op| {
            let range = op_to_combined_input_bits_range(op);
            range.end.checked_sub(range.start).unwrap()
        })
        .try_fold(0, u128::checked_add)
        .unwrap();

    let float_name = F::short_lowercase_name();
    println!("Exhaustively checking {num_total_cases} cases for {float_name}:");

    // HACK(eddyb) show some indication of progress at least every few seconds,
    // but also don't show verbose progress as often, with fewer testcases.
    let num_dots = usize::try_from(num_total_cases >> 23)
        .unwrap_or(usize::MAX)
        .max(if verbose { 10 } else { 40 });
    let cases_per_dot =
        usize::try_from(num_total_cases / u128::try_from(num_dots).unwrap()).unwrap();

    // Spawn worker threads and only report back from them once in a while
    // (in large batches of successes), or in case of any failure.
    let num_threads = std::thread::available_parallelism().unwrap();
    let successes_batch_size = (cases_per_dot / num_threads).next_power_of_two();

    struct Update<T> {
        successes: usize,
        mismatch_or_panic: Option<(T, Option<Box<dyn std::any::Any + Send>>)>,
    }
    impl<T> Default for Update<T> {
        fn default() -> Self {
            Update {
                successes: 0,
                mismatch_or_panic: None,
            }
        }
    }
    let (updates_tx, updates_rx) = std::sync::mpsc::channel();

    // HACK(eddyb) avoid reporting panics while iterating.
    std::panic::set_hook(Box::new(|_| {}));

    let worker_threads: Vec<_> = (0..num_threads.get())
        .map(|thread_idx| {
            let cli_args = cli_args.clone();
            let updates_tx = updates_tx.clone();
            let cases_per_thread = all_ops
                .clone()
                .flat_map(op_to_exhaustive_cases)
                .skip(thread_idx)
                .step_by(num_threads.get());
            std::thread::spawn(move || {
                let mut update = Update::default();
                for op_with_inputs in cases_per_thread {
                    // HACK(eddyb) there are still panics we need to account for,
                    // e.g. https://github.com/llvm/llvm-project/issues/63895, and
                    // even if the Rust code didn't panic, LLVM asserts would trip.
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        op_with_inputs.eval(&cli_args)
                    })) {
                        Ok(out) => {
                            if out.all_match() {
                                update.successes += 1;
                            } else {
                                update.mismatch_or_panic = Some((op_with_inputs, None));
                            }
                        }
                        Err(panic) => {
                            update.mismatch_or_panic = Some((op_with_inputs, Some(panic)));
                        }
                    }

                    if update.successes >= successes_batch_size
                        || update.mismatch_or_panic.is_some()
                    {
                        updates_tx.send(mem::take(&mut update)).unwrap();
                    }
                }
                updates_tx.send(update).unwrap();
            })
        })
        .collect();

    // HACK(eddyb) ensure that `Sender`s are only tied to active threads,
    // allowing the `for` loop below to exit, once all worker threads finish.
    drop(updates_tx);

    let mut case_idx = 0;
    let mut current_dot_first_case_idx = 0;
    let mut last_mismatch_case_idx = None;
    let mut last_panic_case_idx = None;
    let mut all_mismatches = vec![];
    let mut all_panics = vec![];
    let mut verbose_failed_to_show_some_panics = false;
    for update in updates_rx {
        let Update {
            successes,
            mismatch_or_panic,
        } = update;
        let successes_and_failures = [
            Some(successes).filter(|&n| n > 0).map(Ok),
            mismatch_or_panic.map(Err),
        ]
        .into_iter()
        .flatten();

        for success_or_failure in successes_and_failures {
            match success_or_failure {
                Ok(successes) => case_idx += successes,

                Err((op_with_inputs, None)) => {
                    if verbose {
                        op_with_inputs.print_op_and_eval_outputs(cli_args);
                    }

                    last_mismatch_case_idx = Some(case_idx);
                    all_mismatches.push(op_with_inputs);

                    case_idx += 1;
                }

                Err((op_with_inputs, Some(panic))) => {
                    if verbose {
                        op_with_inputs.print_op_and_eval_outputs(&cli_args_plus_ignore_cxx);
                        if let Ok(msg) = panic.downcast::<String>() {
                            eprintln!("panicked with: {msg}");
                        } else {
                            verbose_failed_to_show_some_panics = true;
                        }
                    }

                    last_panic_case_idx = Some(case_idx);
                    all_panics.push(op_with_inputs);

                    case_idx += 1;
                }
            }

            loop {
                let next_dot_first_case_idx = current_dot_first_case_idx + cases_per_dot;
                if case_idx < next_dot_first_case_idx {
                    break;
                }
                if verbose {
                    println!(
                        "  {:3.1}% done ({case_idx} / {num_total_cases}), \
                           found {} mismatches and {} panics",
                        (case_idx as f64) / (num_total_cases as f64) * 100.0,
                        all_mismatches.len(),
                        all_panics.len()
                    );
                } else {
                    print!(
                        "{}",
                        if last_panic_case_idx.is_some_and(|i| i >= current_dot_first_case_idx) {
                            '🕱'
                        } else if last_mismatch_case_idx
                            .is_some_and(|i| i >= current_dot_first_case_idx)
                        {
                            '≠'
                        } else {
                            '.'
                        }
                    );
                    // HACK(eddyb) get around `stdout` line buffering.
                    std::io::stdout().flush().unwrap();
                }
                current_dot_first_case_idx = next_dot_first_case_idx;
            }
        }
    }
    println!();

    // HACK(eddyb) undo what we did just before spawning worker threads.
    let _ = std::panic::take_hook();

    for worker_thread in worker_threads {
        worker_thread.join().unwrap();
    }

    // HACK(eddyb) keep only one mismatch per `FuzzOp` variant.
    // FIXME(eddyb) consider sorting these (and panics?) due to parallelism.
    let num_mismatches = all_mismatches.len();
    let mut select_mismatches = all_mismatches;
    select_mismatches.dedup_by_key(|op_with_inputs| op_with_inputs.tag());

    if num_mismatches > 0 {
        println!();
        println!(
            "⚠ found {num_mismatches} ({:.1}%) mismatches for {float_name}, showing {} of them:",
            (num_mismatches as f64) / (num_total_cases as f64) * 100.0,
            select_mismatches.len(),
        );
        for mismatch in select_mismatches {
            mismatch.print_op_and_eval_outputs(cli_args);
        }
    }

    if !all_panics.is_empty() {
        println!();
        println!(
            "⚠ found {} panics for {float_name}, {}",
            all_panics.len(),
            if verbose && !verbose_failed_to_show_some_panics {
                "shown above"
            } else {
                "showing them (without trying C++):"
            },
        );
        if !verbose || verbose_failed_to_show_some_panics {
            for &panicking_case in &all_panics {
                panicking_case.print_op_and_eval_outputs(&cli_args_plus_ignore_cxx);
            }
        }
    }

    if num_mismatches == 0 && all_panics.is_empty() {
        println!("✔️ all {num_total_cases} cases match");
    }
    println!();

    NonZeroUsize::new(num_mismatches + all_panics.len()).map_or(Ok(()), Err)
}
