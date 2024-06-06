use game::play_game;

//在测试过程中，main函数可以为空，但是不能没有，使用cargo bench命令会自动走测试，并不走main函数

fn main() {
    for i in 1..=100 {
        play_game(i, true);
    }
}
