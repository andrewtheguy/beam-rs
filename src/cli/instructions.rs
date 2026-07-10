pub fn print_receiver_command(command: &str) {
    beam_rs::ui::info("On the receiving end, run:");
    beam_rs::ui::info(&format!("  {}\n", command));
}
