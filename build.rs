extern crate cc;

fn main() {

        let mut build = cc::Build::new();
        let sources = ::std::fs::read_dir("libfuzzer")
            .expect("listable source directory")
            .map(|de| de.expect("file in directory").path())
            .filter(|p| p.extension().map(|ext| ext == "cpp") == Some(true))
            .collect::<Vec<_>>();
        for source in sources.iter() {
            build.file(source.to_str().unwrap());
        }
        build.flag("-std=c++11");
        build.flag("-fno-omit-frame-pointer");
        build.flag("-w");
        build.cpp(true);
        build.compile("libfuzzer.a");
}
