// Run the production native handoff with a synthetic session for browser tests.
#[path = "../src-tauri/src/local_dashboard.rs"]
mod local_dashboard;

fn main() {
    let handoff = local_dashboard::Handoff::new(
        &format!("oass_{}", "a".repeat(43)), &"b".repeat(43),
        std::env::args().nth(1).unwrap().parse().unwrap(),
    ).unwrap();
    println!("{}", handoff.url());
    handoff.serve(std::time::Duration::from_secs(30));
}
