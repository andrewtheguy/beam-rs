pub fn print_receiver_command(command: &str) {
    let sink = beam_common::ui::sink();
    sink.info("On the receiving end, run:");
    sink.info(&format!("  {}\n", command));
}
