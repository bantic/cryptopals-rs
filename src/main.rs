use cryptopals_rs::set1;

fn main() {
    set1::challenge1();
    println!("-----------------------");
    set1::challenge2();
    println!("-----------------------");
    set1::challenge3();
    println!("-----------------------");
    set1::challenge4();
    println!("-----------------------");
    set1::challenge5();
    println!("-----------------------");

    let chal_6_input = include_str!("./set1/data/challenge6.txt");
    let chal_6_input = chal_6_input.replace('\n', "");
    println!("{}", chal_6_input);
}
