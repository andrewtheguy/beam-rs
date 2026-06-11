//! Inline terminal UI for beam transfers (enabled by the `tui` feature).
//!
//! This implements a [`UiSink`] that renders an *inline* live region at the
//! bottom of the terminal — a phase label, a progress gauge, and a hint — while
//! status/log lines and the beam code scroll into normal terminal history above
//! it (à la `apt`). It never uses the alternate screen.
//!
//! ## Design
//!
//! The render loop runs on a **dedicated OS thread** with its own
//! current-thread Tokio runtime. That keeps it alive even when the transfer's
//! blocking prompt calls ([`UiSink::prompt_file_exists`] etc.) park a worker
//! thread of the main runtime waiting for the user's answer.
//!
//! Communication is one channel of [`UiEvent`]s from the sink to the loop.
//! Prompts piggy-back a [`std::sync::mpsc`] reply sender on the event and block
//! the caller until the loop sends the user's response back.
//!
//! Cancellation (`q` / Ctrl-C in the live region) restores the terminal and, on
//! unix, re-raises `SIGINT` so the existing Ctrl-C cleanup handlers run exactly
//! as in plain mode; on other platforms it exits with code 130.

use std::io;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::mpsc as stdmpsc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use crossterm::cursor::{MoveTo, Show};
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::{execute, queue};
use crossterm::style::{Attribute, Print, SetAttribute};
use crossterm::terminal::{Clear, ClearType, disable_raw_mode};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Gauge, Paragraph, Widget, Wrap};
use ratatui::{DefaultTerminal, Frame, TerminalOptions, Viewport};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::core::transfer::{FileExistsChoice, calc_percent, format_bytes};
use crate::ui::{Phase, Progress, UiSink};

/// Height (rows) of the inline viewport. Sized to fit the multi-line prompts.
const VIEWPORT_HEIGHT: u16 = 6;
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Restore the terminal after the TUI exits.
///
/// Each [`Terminal::draw`] renders with no cursor position, so ratatui hides the
/// cursor on every frame (`ESC[?25l`) but never re-shows it. We deliberately do
/// *not* use `ratatui::try_restore` here: it emits `LeaveAlternateScreen`, whose
/// cursor-restore step re-hides the cursor on some terminals — and we never
/// entered the alternate screen anyway (the inline viewport doesn't). So the
/// correct teardown is simply: leave raw mode and show the cursor (last, so
/// `ESC[?25h` is the final byte and nothing can undo it).
fn restore_terminal() {
    let _ = disable_raw_mode();
    let mut out = io::stdout();
    let _ = execute!(out, Show);
    let _ = out.flush();
}

// ============================================================================
// Public entry points
// ============================================================================

/// Detect whether an interactive TUI should run and, if so, start it and
/// install its sink as the process-wide [`crate::ui`] sink.
///
/// Returns `None` (leaving the default plain sink in place) when `no_tui` is
/// set or when stdout/stderr is not a terminal — the "auto-detect" fallback.
pub fn decide_and_install(no_tui: bool) -> Option<TuiHandle> {
    use std::io::IsTerminal;

    if no_tui || !io::stdout().is_terminal() || !io::stderr().is_terminal() {
        return None;
    }

    let mut handle = start()?;
    let sink = handle.take_sink();
    if crate::ui::install(sink) {
        Some(handle)
    } else {
        // Another sink was already installed; tear our loop back down.
        handle.finish();
        None
    }
}

/// Start the inline TUI render loop on a dedicated thread.
///
/// Returns `None` if the terminal cannot be initialized for an inline viewport
/// (e.g. it doesn't answer the cursor-position query), so callers transparently
/// fall back to plain output instead of crashing.
pub fn start() -> Option<TuiHandle> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<UiEvent>();
    // Signals whether terminal init succeeded on the render thread.
    let (init_tx, init_rx) = stdmpsc::channel::<bool>();

    let join = std::thread::Builder::new()
        .name("beam-tui".into())
        .spawn(move || {
            let mut terminal = match ratatui::try_init_with_options(TerminalOptions {
                viewport: Viewport::Inline(VIEWPORT_HEIGHT),
            }) {
                Ok(terminal) => {
                    let _ = init_tx.send(true);
                    terminal
                }
                Err(_) => {
                    let _ = init_tx.send(false);
                    restore_terminal();
                    return;
                }
            };

            // Guard against a render-loop panic leaving the terminal in raw mode.
            // The loop is fully synchronous: a concurrent stdin reader (e.g. an
            // async EventStream) would steal the cursor-position responses that
            // inline `insert_before` blocks on, so input is polled inline here.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = render_loop(&mut terminal, rx);
            }));
            // Best-effort restore (a cancel path may already have restored).
            restore_terminal();
        })
        .expect("failed to spawn TUI thread");

    match init_rx.recv() {
        Ok(true) => {
            let sink: Box<dyn UiSink> = Box::new(TuiSink { tx: tx.clone() });
            Some(TuiHandle {
                join,
                finish_tx: tx,
                sink: Some(sink),
            })
        }
        // Init failed (or thread died) — join and fall back to plain mode.
        _ => {
            let _ = join.join();
            None
        }
    }
}

/// Handle to a running inline TUI.
pub struct TuiHandle {
    join: std::thread::JoinHandle<()>,
    finish_tx: UnboundedSender<UiEvent>,
    sink: Option<Box<dyn UiSink>>,
}

impl TuiHandle {
    /// Take the sink to install via [`crate::ui::install`]. Panics if called twice.
    pub fn take_sink(&mut self) -> Box<dyn UiSink> {
        self.sink.take().expect("TUI sink already taken")
    }

    /// Stop the render loop and restore the terminal, blocking until done.
    pub fn finish(self) {
        let _ = self.finish_tx.send(UiEvent::Finish);
        let _ = self.join.join();
    }
}

// ============================================================================
// Sink → loop messaging
// ============================================================================

/// User's reply to a prompt, sent from the render loop back to the sink.
enum PromptReply {
    FileExists(FileExistsChoice),
    Bool(bool),
    Line(Result<String, String>),
}

/// A prompt the render loop must present and resolve.
enum PromptKind {
    FileExists(PathBuf),
    LargeFolder { size: u64, name: String },
    Line { prompt: String, initial: String },
}

/// Messages from the [`TuiSink`] to the render loop.
enum UiEvent {
    Status(String),
    Info(String),
    Progress(Progress),
    ProgressEnd,
    Code(String),
    Pin(String),
    Phase(Phase),
    Prompt {
        kind: PromptKind,
        reply: stdmpsc::Sender<PromptReply>,
    },
    Finish,
}

/// The TUI [`UiSink`]: forwards output to the render loop over a channel and
/// blocks on prompt replies.
struct TuiSink {
    tx: UnboundedSender<UiEvent>,
}

impl TuiSink {
    fn ask(&self, kind: PromptKind) -> Result<PromptReply> {
        let (rtx, rrx) = stdmpsc::channel();
        self.tx
            .send(UiEvent::Prompt { kind, reply: rtx })
            .map_err(|_| anyhow!("TUI closed"))?;
        rrx.recv().map_err(|_| anyhow!("TUI closed"))
    }
}

impl UiSink for TuiSink {
    fn status(&self, line: &str) {
        let _ = self.tx.send(UiEvent::Status(line.to_string()));
    }
    fn info(&self, line: &str) {
        let _ = self.tx.send(UiEvent::Info(line.to_string()));
    }
    fn progress(&self, p: Progress) {
        let _ = self.tx.send(UiEvent::Progress(p));
    }
    fn progress_end(&self) {
        let _ = self.tx.send(UiEvent::ProgressEnd);
    }
    fn show_code(&self, code: &str) {
        let _ = self.tx.send(UiEvent::Code(code.to_string()));
    }
    fn show_pin(&self, pin: &str) {
        let _ = self.tx.send(UiEvent::Pin(pin.to_string()));
    }
    fn set_phase(&self, phase: Phase) {
        let _ = self.tx.send(UiEvent::Phase(phase));
    }

    fn prompt_file_exists(&self, path: &std::path::Path) -> Result<FileExistsChoice> {
        match self.ask(PromptKind::FileExists(path.to_path_buf()))? {
            PromptReply::FileExists(c) => Ok(c),
            _ => Err(anyhow!("unexpected prompt reply")),
        }
    }

    fn confirm_large_folder(&self, size: u64, name: &str) -> Result<bool> {
        match self.ask(PromptKind::LargeFolder {
            size,
            name: name.to_string(),
        })? {
            PromptReply::Bool(b) => Ok(b),
            _ => Err(anyhow!("unexpected prompt reply")),
        }
    }

    fn prompt_line(&self, prompt: &str, initial: &str) -> Result<String> {
        match self.ask(PromptKind::Line {
            prompt: prompt.to_string(),
            initial: initial.to_string(),
        })? {
            PromptReply::Line(Ok(s)) => Ok(s),
            PromptReply::Line(Err(e)) => Err(anyhow!(e)),
            _ => Err(anyhow!("unexpected prompt reply")),
        }
    }
}

// ============================================================================
// Render loop
// ============================================================================

/// Live-region state.
struct App {
    phase: Phase,
    progress: Option<Progress>,
    spinner: usize,
}

/// How long each input poll waits; doubles as the live-region frame interval.
const FRAME_POLL: Duration = Duration::from_millis(80);

fn render_loop(terminal: &mut DefaultTerminal, mut rx: UnboundedReceiver<UiEvent>) -> io::Result<()> {
    let mut app = App {
        phase: Phase::Preparing,
        progress: None,
        spinner: 0,
    };

    terminal.draw(|f| render_live(f, &app))?;

    loop {
        // Drain all pending UI events (status → scrollback, progress → state).
        loop {
            match rx.try_recv() {
                Ok(UiEvent::Finish) => return Ok(()),
                Ok(UiEvent::Status(s)) | Ok(UiEvent::Info(s)) => {
                    insert_lines(terminal, plain_lines(&s))?;
                }
                Ok(UiEvent::Code(c)) => {
                    insert_lines(
                        terminal,
                        vec![
                            Line::from(""),
                            Line::from(Span::styled("🔮 Beam code:", Style::new().cyan().bold())),
                        ],
                    )?;
                    insert_code_raw(terminal, &c)?;
                    insert_lines(terminal, vec![Line::from("")])?;
                }
                Ok(UiEvent::Pin(p)) => insert_lines(terminal, pin_lines(&p))?,
                Ok(UiEvent::Progress(p)) => {
                    app.progress = Some(p);
                    app.phase = Phase::Transferring;
                }
                Ok(UiEvent::ProgressEnd) => {}
                Ok(UiEvent::Phase(ph)) => app.phase = ph,
                Ok(UiEvent::Prompt { kind, reply }) => {
                    let r = run_prompt(terminal, kind)?;
                    let _ = reply.send(r);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }

        // Poll for a key press (also paces the frame). Reading input inline —
        // never from a concurrent thread — keeps `insert_before`'s cursor
        // queries from being stolen.
        if event::poll(FRAME_POLL)?
            && let Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
            && is_cancel_key(&k)
        {
            cancel_and_exit(terminal);
            return Ok(());
        }

        app.spinner = app.spinner.wrapping_add(1);
        terminal.draw(|f| render_live(f, &app))?;
    }
}

fn terminal_width(terminal: &DefaultTerminal) -> u16 {
    terminal.size().map(|s| s.width).unwrap_or(80).max(8)
}

/// Restore the terminal and trigger the normal interrupt path.
fn cancel_and_exit(terminal: &mut DefaultTerminal) {
    let _ = terminal.clear();
    restore_terminal();
    #[cfg(unix)]
    // SAFETY: raising a signal is async-signal-safe and has no preconditions.
    unsafe {
        libc::raise(libc::SIGINT);
    }
    #[cfg(not(unix))]
    std::process::exit(130);
}

fn is_cancel_key(k: &KeyEvent) -> bool {
    matches!(k.code, KeyCode::Char('q'))
        || (matches!(k.code, KeyCode::Char('c')) && k.modifiers.contains(KeyModifiers::CONTROL))
}

// ============================================================================
// Live-region rendering
// ============================================================================

fn phase_label(p: Phase) -> &'static str {
    match p {
        Phase::Preparing => "Preparing",
        Phase::Waiting => "Waiting for peer",
        Phase::Connecting => "Connecting",
        Phase::Authenticating => "Authenticating",
        Phase::Transferring => "Transferring",
        Phase::Finalizing => "Finalizing",
        Phase::Done => "Done",
    }
}

fn render_live(f: &mut Frame, app: &App) {
    let area = f.area();
    let rows = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Length(1), // gauge
        Constraint::Length(1), // detail
        Constraint::Length(1), // hint
        Constraint::Min(0),    // padding
    ])
    .split(area);

    let spin = SPINNER[app.spinner % SPINNER.len()];
    let title = Line::from(vec![
        Span::styled("🔮 beam-rs ", Style::new().cyan().bold()),
        Span::raw("— "),
        Span::styled(phase_label(app.phase), Style::new().bold()),
        Span::raw(" "),
        Span::raw(if app.phase == Phase::Done { "" } else { spin }),
    ]);
    f.render_widget(Paragraph::new(title), rows[0]);

    match app.progress {
        Some(p) if p.total > 0 => {
            let ratio = (calc_percent(p.bytes, p.total) / 100.0).clamp(0.0, 1.0);
            let pct = (ratio * 100.0) as u16;
            f.render_widget(
                Gauge::default()
                    .gauge_style(Style::new().cyan())
                    .ratio(ratio)
                    .label(format!("{pct}%")),
                rows[1],
            );
            let mut detail = format!("{} / {}", format_bytes(p.bytes), format_bytes(p.total));
            if let Some((chunk, total)) = p.chunk {
                detail.push_str(&format!("  ·  chunk {chunk}/{total}"));
            }
            f.render_widget(Paragraph::new(detail).dim(), rows[2]);
        }
        _ => {
            f.render_widget(Paragraph::new("").dim(), rows[1]);
            f.render_widget(Paragraph::new("").dim(), rows[2]);
        }
    }

    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "press q to cancel",
            Style::new().dim(),
        ))),
        rows[3],
    );
}

// ============================================================================
// Scrollback helpers (insert_before)
// ============================================================================

/// Insert `lines` into the scrollback above the inline viewport.
fn insert_lines(terminal: &mut DefaultTerminal, lines: Vec<Line<'static>>) -> io::Result<()> {
    if lines.is_empty() {
        return Ok(());
    }
    let height = lines.len() as u16;
    let text = Text::from(lines);
    terminal.insert_before(height, |buf: &mut Buffer| {
        Paragraph::new(text).render(buf.area, buf);
    })
}

/// Split a (possibly `\n`-prefixed) message into display lines.
fn plain_lines(s: &str) -> Vec<Line<'static>> {
    s.split('\n').map(|l| Line::from(l.to_string())).collect()
}

fn pin_lines(pin: &str) -> Vec<Line<'static>> {
    vec![
        Line::from(vec![
            Span::raw("🔢 PIN: "),
            Span::styled(pin.to_string(), Style::new().yellow().bold()),
        ]),
        Line::from(""),
    ]
}

/// Insert the beam code into scrollback as a single, soft-wrapped logical line.
///
/// [`insert_lines`] renders through ratatui's fixed-width grid, which hard-wraps
/// a long code into separate terminal rows padded with spaces — so selecting it
/// from scrollback yields a string broken by newlines. Instead, this reserves
/// the exact number of rows the code needs (which also repositions the
/// viewport), then writes the code in *one continuous write* and lets the
/// terminal autowrap it. The code therefore renders — and copies — as one
/// unbroken line.
fn insert_code_raw(terminal: &mut DefaultTerminal, code: &str) -> io::Result<()> {
    let width = terminal_width(terminal);
    let rows = code.chars().count().div_ceil(width as usize).max(1);

    // We can only raw-write rows that are currently on screen. If the block plus
    // the viewport wouldn't fit, fall back to the grid (hard-wrapped) path.
    if rows + VIEWPORT_HEIGHT as usize > terminal.size()?.height as usize {
        let lines = wrap_chars(code, width as usize)
            .into_iter()
            .map(|c| Line::from(Span::styled(c, Style::new().bold())))
            .collect();
        return insert_lines(terminal, lines);
    }

    // Reserve `rows` blank rows above the viewport. The empty draw closure means
    // we only borrow the scrolling/positioning bookkeeping; the cells are
    // overwritten below. `insert_before` updates the viewport area, which we
    // then read back to find the top of the reserved region.
    terminal.insert_before(rows as u16, |_buf| {})?;
    let start_y = terminal.get_frame().area().y.saturating_sub(rows as u16);

    let out = terminal.backend_mut();
    queue!(
        out,
        MoveTo(0, start_y),
        SetAttribute(Attribute::Bold),
        Print(code),
        SetAttribute(Attribute::Reset),
        // Wipe the blank cells `insert_before` left on the final wrapped row.
        Clear(ClearType::UntilNewLine),
    )?;
    out.flush()
}

/// Wrap an ASCII string into chunks of at most `width` characters so a long
/// beam code is fully shown (and copyable) instead of being clipped.
fn wrap_chars(s: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return vec![String::new()];
    }
    chars
        .chunks(width)
        .map(|c| c.iter().collect::<String>())
        .collect()
}

// ============================================================================
// Prompt modals
// ============================================================================

fn run_prompt(terminal: &mut DefaultTerminal, kind: PromptKind) -> io::Result<PromptReply> {
    match kind {
        PromptKind::FileExists(path) => {
            let body = vec![
                Line::from(vec![
                    Span::raw("⚠️  File exists: "),
                    Span::styled(path.display().to_string(), Style::new().bold()),
                ]),
                Line::from(""),
                Line::from("[o]verwrite   [r]ename   [c]ancel"),
            ];
            loop {
                draw_modal(terminal, &body)?;
                let k = next_key_event()?;
                if is_cancel_key(&k) {
                    return Ok(PromptReply::FileExists(FileExistsChoice::Cancel));
                }
                match k.code {
                    KeyCode::Char('o') => {
                        return Ok(PromptReply::FileExists(FileExistsChoice::Overwrite));
                    }
                    KeyCode::Char('r') => {
                        return Ok(PromptReply::FileExists(FileExistsChoice::Rename));
                    }
                    KeyCode::Char('c') | KeyCode::Esc => {
                        return Ok(PromptReply::FileExists(FileExistsChoice::Cancel));
                    }
                    _ => {}
                }
            }
        }
        PromptKind::LargeFolder { size, name } => {
            let body = vec![
                Line::from(vec![
                    Span::raw("⚠️  Warning: "),
                    Span::styled(name, Style::new().bold()),
                    Span::raw(format!(" is large ({}).", format_bytes(size))),
                ]),
                Line::from("Folder transfers are NOT resumable; if interrupted you start over."),
                Line::from("Recommended for local connections only (send --local-only)."),
                Line::from(""),
                Line::from("Continue anyway?  [y]es   [N]o"),
            ];
            loop {
                draw_modal(terminal, &body)?;
                let k = next_key_event()?;
                if is_cancel_key(&k) {
                    return Ok(PromptReply::Bool(false));
                }
                match k.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => return Ok(PromptReply::Bool(true)),
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc | KeyCode::Enter => {
                        return Ok(PromptReply::Bool(false));
                    }
                    _ => {}
                }
            }
        }
        PromptKind::Line { prompt, initial } => run_line_prompt(terminal, &prompt, initial),
    }
}

/// Run an editable, readline-style single-line prompt.
///
/// Mirrors the non-TUI (rustyline) input: the cursor can move through the text
/// (←/→, Home/End, Ctrl-A/E) and edits happen at the cursor (insert, Backspace,
/// Delete, Ctrl-U/K/W), so a pasted beam code can be corrected mid-string.
/// Bracketed paste is enabled so a paste arrives as one chunk instead of a
/// flood of key events.
fn run_line_prompt(
    terminal: &mut DefaultTerminal,
    prompt: &str,
    initial: String,
) -> io::Result<PromptReply> {
    let _ = execute!(io::stdout(), EnableBracketedPaste);
    let result = line_editor(terminal, prompt, initial);
    let _ = execute!(io::stdout(), DisableBracketedPaste);
    result
}

fn line_editor(
    terminal: &mut DefaultTerminal,
    prompt: &str,
    initial: String,
) -> io::Result<PromptReply> {
    let mut chars: Vec<char> = initial.chars().collect();
    let mut cursor = chars.len();

    loop {
        draw_line_modal(terminal, prompt, &chars, cursor)?;

        match next_input_event()? {
            Event::Paste(s) => {
                for c in s.chars().filter(|c| !c.is_control()) {
                    chars.insert(cursor, c);
                    cursor += 1;
                }
            }
            Event::Key(k) => {
                let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
                match k.code {
                    KeyCode::Enter => {
                        return Ok(PromptReply::Line(Ok(chars.into_iter().collect())));
                    }
                    KeyCode::Esc => return Ok(PromptReply::Line(Err("cancelled".into()))),
                    KeyCode::Char('c') if ctrl => {
                        return Ok(PromptReply::Line(Err("Interrupted".into())));
                    }
                    // Cursor movement.
                    KeyCode::Left => cursor = cursor.saturating_sub(1),
                    KeyCode::Right if cursor < chars.len() => cursor += 1,
                    KeyCode::Home => cursor = 0,
                    KeyCode::End => cursor = chars.len(),
                    KeyCode::Char('a') if ctrl => cursor = 0,
                    KeyCode::Char('e') if ctrl => cursor = chars.len(),
                    // Editing.
                    KeyCode::Char('u') if ctrl => {
                        chars.drain(..cursor);
                        cursor = 0;
                    }
                    KeyCode::Char('k') if ctrl => chars.truncate(cursor),
                    KeyCode::Char('w') if ctrl => {
                        let start = prev_word_boundary(&chars, cursor);
                        chars.drain(start..cursor);
                        cursor = start;
                    }
                    KeyCode::Backspace if cursor > 0 => {
                        cursor -= 1;
                        chars.remove(cursor);
                    }
                    KeyCode::Delete if cursor < chars.len() => {
                        chars.remove(cursor);
                    }
                    // Plain text entry (ignore control-modified chars).
                    KeyCode::Char(c) if !ctrl => {
                        chars.insert(cursor, c);
                        cursor += 1;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

/// Index of the start of the word before `cursor` (for Ctrl-W).
fn prev_word_boundary(chars: &[char], cursor: usize) -> usize {
    let mut i = cursor;
    while i > 0 && chars[i - 1].is_whitespace() {
        i -= 1;
    }
    while i > 0 && !chars[i - 1].is_whitespace() {
        i -= 1;
    }
    i
}

/// Draw the line-prompt modal with a block cursor at `cursor`.
fn draw_line_modal(
    terminal: &mut DefaultTerminal,
    prompt: &str,
    chars: &[char],
    cursor: usize,
) -> io::Result<()> {
    let left: String = chars[..cursor].iter().collect();
    let mut input = vec![Span::raw("> "), Span::raw(left)];
    if cursor < chars.len() {
        // Block cursor over the character it sits on.
        input.push(Span::styled(chars[cursor].to_string(), Style::new().reversed()));
        input.push(Span::raw(chars[cursor + 1..].iter().collect::<String>()));
    } else {
        input.push(Span::styled(" ", Style::new().reversed()));
    }

    let body = vec![
        Line::from(Span::styled(prompt.to_string(), Style::new().bold())),
        Line::from(input),
        Line::from(""),
        Line::from(Span::styled(
            "←/→ move · Enter confirm · Esc cancel",
            Style::new().dim(),
        )),
    ];
    draw_modal(terminal, &body)
}

/// Block until the next key press or paste (ignoring releases/other events).
fn next_input_event() -> io::Result<Event> {
    loop {
        match event::read()? {
            ev @ Event::Key(k) if k.kind == KeyEventKind::Press => return Ok(ev),
            ev @ Event::Paste(_) => return Ok(ev),
            _ => {}
        }
    }
}

/// Draw a prompt modal that fills the inline viewport.
fn draw_modal(terminal: &mut DefaultTerminal, body: &[Line<'static>]) -> io::Result<()> {
    let text = Text::from(body.to_vec());
    terminal.draw(|f| {
        f.render_widget(
            Paragraph::new(text.clone()).wrap(Wrap { trim: false }),
            f.area(),
        );
    })?;
    Ok(())
}

/// Block until the next key press (ignoring releases/non-key events).
fn next_key_event() -> io::Result<KeyEvent> {
    loop {
        if let Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
        {
            return Ok(k);
        }
    }
}
