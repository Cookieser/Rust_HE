//这个地方是定义库包内容的默认位置，模块的名字是项目的名字，这里是game：...（在cargo配置中也可查看）
//定义了两个函数，实现了解藕

pub fn play_game(n: u32, print: bool) {
    let result = fizz_buzz(n);
    if print {
        println!("{result}");
    }
}

pub fn fizz_buzz(n: u32) -> String {
    match (n % 3, n % 5) {
        (0, 0) => "FizzBuzz".to_string(),
        (0, _) => "Fizz".to_string(),
        (_, 0) => "Buzz".to_string(),
        (_, _) => n.to_string(),
    }
}