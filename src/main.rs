use cryptopals_rs::set1;
use cryptopals_rs::set2;
use cryptopals_rs::MyResult;

fn main() -> MyResult<()> {
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
    set1::challenge6()?;
    println!("-----------------------");
    set1::challenge7()?;
    println!("-----------------------");
    set1::challenge8()?;
    println!("-----------------------");
    set2::challenge9();
    println!("-----------------------");
    set2::challenge10()?;
    println!("-----------------------");
    set2::challenge11()?;
    println!("-----------------------");
    Ok(())
}
