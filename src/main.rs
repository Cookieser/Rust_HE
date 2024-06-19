
extern crate game;
use game::mul;
//use game::Timer;
// fn main() {
//     let mut timer = Timer::new();
//     let handle = timer.register("Test Timer");
    
//     // 代码块开始计时
//     timer.tick(handle);
//     // 模拟一些代码执行
//     std::thread::sleep(std::time::Duration::from_millis(500));
//     // 代码块结束计时
//     timer.tock(handle);
    
//     // 打印计时结果
//     timer.print();
// }



fn main(){

    mul::min_function();
    mul::max_function();

}