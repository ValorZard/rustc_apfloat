# Allow overriding the fuzz directories
fuzz_in := env("FUZZ_IN", "fuzz/runs/in")
fuzz_out := env("FUZZ_OUT", "fuzz/runs/out")

alias f := fuzz
alias fp := fuzz-parallel
alias fa := fuzz-attach
alias fq := fuzz-parallel-quit
alias d := decode
alias t := test

_default:
    {{ just_executable() }} --list

# Run non-fuzzing tests
test:
    cargo test --workspace

# Create directories and build the executable, but don't start fuzzing.
_fuzz-setup:
    mkdir -p "{{ fuzz_in }}"
    echo > "{{ fuzz_in }}/empty"
    cargo afl build -p rustc_apfloat-fuzz --release

# Build the instrumented executable and fuzz it. See also: `fuzz-parallel`.
fuzz: _fuzz-setup
    cargo afl fuzz -i "{{ fuzz_in }}" -o "{{ fuzz_out }}" target/release/rustc_apfloat-fuzz

# Start fuzzing in parallel. Note this must be stopped with fuzz-parallel-quit (see fuzz-parallel.sh).
fuzz-parallel *args: _fuzz-setup
    etc/fuzz-parallel.sh {{ args }}

# Attach to a running parallel fuzz session
fuzz-attach:
    tmux attach -t afl01

# Stop parallel fuzzing
fuzz-parallel-quit:
    tmux list-sessions | cut -d':' -f1 | grep afl | xargs -iSESS tmux kill-session -t SESS

all-crashes := '"' + fuzz_out + '"/*/crashes/*'

# Print the result of crashes in the fuzz output directory
decode *paths=all-crashes:
    ls {{ all-crashes }}
    cargo run -p rustc_apfloat-fuzz -- decode {{ paths }}
