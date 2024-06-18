//核心测试部分代码
//导入Criterion基准测试运行器
use criterion::{criterion_group, criterion_main, Criterion};

use game::play_game;

fn bench_play_game(c: &mut Criterion) {
    c.bench_function("bench_play_game", |b| {
        b.iter(|| {
            std::hint::black_box(for i in 1..=100 {
                play_game(i, false)
            });
        });
    });
}
//用于创建一个基准测试组。这里定义了一个名为 benches 的基准测试组，包含 bench_play_game 函数。
criterion_group!(
    benches,
    bench_play_game,
);
//定义基准测试的入口点。这个入口点会运行 benches 组中的所有基准测试。
criterion_main!(benches);
