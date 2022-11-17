//TODO: implement (make this return something instead of printing and use that value)
///checks for invisible/zero-width characters in names and deletes them. 
pub fn main(){
    //TODO next: check for initial and final whitespace
    use std::char;
    let disallowed_chars: [u32; 53] = [0x202e,0x0009,0x00AD,0x034F,0x061C,0x115F,0x1160,0x17B4,0x17B5,0x180E,0x2000,0x2001,0x2002,0x2003,0x2004,0x2005,0x2006,0x2007,0x2008,0x2009,0x200A,0x200B,0x200C,0x200D,0x200E,0x200F,0x202F,0x205F,0x2060,0x2061,0x2062,0x2063,0x2064,0x206A,0x206B,0x206C,0x206D,0x206E,0x206F,0x3000,0x2800,0x3164,0xFEFF,0xFFA0,0x1D159,0x1D173,0x1D174,0x1D175,0x1D176,0x1D177,0x1D178,0x1D179,0x1D17A];
    let name_chars = name.chars(); //change this back to name.0.chars()
    // chars() is already an iterator use chars().next() and chars().count() (hover for more info)
    // println!("{}", name_chars);
    let mut fixed_name = String::from("");
    // let mut sanitized_name = String::from("");
    let mut index = 0;
    let mut to_keep:[bool; 32] = [true; 32]; //assuming 32 is the max name size - TODO: figure out how to not hardcode this in rust
    // let mut first_char:bool = false;
    // let mut last_char:usize = 0;
    for i in name_chars{
        for j in 0..disallowed_chars.len(){
            if i == char::from_u32(disallowed_chars[j]).unwrap() {
                to_keep[index] = false;
            }; 
        };
        // if !first_char{
        //     if i == ' '{
        //         to_keep[index] = false;
        //     } else{
        //         first_char = true;
        //     };
        // };
        // if i != ' '{
        //     last_char = index;
        // };
        // index+=1;
    // };
    // if last_char < index{
    //     for i in to_keep{ // i is a bool bc its indexing tokeep
    //         if i > first_char{
    //             to_keep[i] = false;
    //         };
    //     };
    // };
    // index = 0;
    // for i in name_chars{
        if to_keep[index]{
            fixed_name.push(i)
        };
            index += 1;
    };
    //sanitize leading and trailing whitespace
    // while fixed_name[0] == ' '{
    //     fixed_name.remove(0);
    // }
    println!("{}", fixed_name);
}