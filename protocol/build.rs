fn main() {
    prost_build::compile_protos(&["src/ripple.proto"], &["src/"])
        .expect("Compile `src/ripple.proto`");
}
