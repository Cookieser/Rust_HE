完成一个简单的bench demo

[[bench]]
name = "play_game"
harness = false
指定是否使用默认的测试基准框架。如果设置为 false，表示不使用默认的基准框架，而是使用自定义的基准测试逻辑。通常用于 Criterion 这样的库，它有自己的基准测试框架。
在 Cargo.toml 文件中配置基准测试时，[[bench]] 部分的 name 字段确实需要与 benches 目录中的文件名一一对应。这是因为 Rust 的基准测试框架需要通过这些名称来定位和执行相应的基准测试文件。