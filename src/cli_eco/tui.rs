// tui.rs — `kepr ui` state, key handling and layout (T8.02). Pure: no
// terminal or daemon IO here (tui_term.rs drives it). Only credential
// metadata from `List` ever reaches this module; it has no value to draw.
// batch: eco

use kepr_core::protocol::CredInfo;

/// One credential as the list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub kind: String,
    pub tags: Vec<String>,
    pub expires: Option<String>,
    pub flags: Vec<&'static str>,
}

/// The credential's tags, from `kepr list` metadata (T5.01).
fn tags_of(c: &CredInfo) -> Vec<String> {
    c.tags.clone().unwrap_or_default()
}

impl Row {
    pub fn from_info(c: &CredInfo) -> Self {
        let on = |b: Option<bool>| b == Some(true);
        let flags = [
            (on(c.sealed), "sealed"),
            (on(c.requires_consent), "consent"),
            (on(c.requires_fido2), "fido2"),
        ]
        .into_iter()
        .filter_map(|(set, f)| set.then_some(f))
        .collect();
        Row {
            name: c.name.clone(),
            kind: c.record_type.clone().unwrap_or_else(|| "value".into()),
            tags: tags_of(c),
            expires: c.expires_at.clone(),
            flags,
        }
    }

    fn matches(&self, q: &str) -> bool {
        let q = q.to_lowercase();
        self.name.to_lowercase().contains(&q)
            || self.kind.contains(&q)
            || self.tags.iter().any(|t| t.to_lowercase().contains(&q))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Home,
    End,
    Enter,
    Esc,
    Backspace,
    CtrlC,
    Char(char),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Search,
    Confirm(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    Refresh,
    Copy(String),
    Delete(String),
}

#[derive(Debug)]
pub struct State {
    rows: Vec<Row>,
    pub query: String,
    pub cursor: usize,
    pub mode: Mode,
    pub status: String,
}

impl State {
    pub fn new(rows: Vec<Row>) -> Self {
        let mut s = State {
            rows: Vec::new(),
            query: String::new(),
            cursor: 0,
            mode: Mode::Normal,
            status: String::new(),
        };
        s.set_rows(rows);
        s
    }

    pub fn set_rows(&mut self, mut rows: Vec<Row>) {
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        self.rows = rows;
        self.clamp();
    }

    pub fn visible(&self) -> Vec<&Row> {
        self.rows
            .iter()
            .filter(|r| r.matches(&self.query))
            .collect()
    }

    fn clamp(&mut self) {
        self.cursor = self.cursor.min(self.visible().len().saturating_sub(1));
    }

    fn selected(&self) -> Option<String> {
        self.visible().get(self.cursor).map(|r| r.name.clone())
    }

    fn move_by(&mut self, k: Key) -> bool {
        let last = self.visible().len().saturating_sub(1);
        self.cursor = match k {
            Key::Up => self.cursor.saturating_sub(1),
            Key::Down => (self.cursor + 1).min(last),
            Key::Home => 0,
            Key::End => last,
            _ => return false,
        };
        true
    }

    /// Apply one key; the caller performs the returned action.
    pub fn key(&mut self, k: Key) -> Action {
        if k == Key::CtrlC {
            return Action::Quit;
        }
        match self.mode.clone() {
            Mode::Confirm(name) => {
                self.mode = Mode::Normal;
                if matches!(k, Key::Char('y' | 'Y')) {
                    return Action::Delete(name);
                }
                self.status = format!("kept {name}");
                Action::None
            }
            Mode::Search => {
                match k {
                    Key::Char(c) => self.query.push(c),
                    Key::Backspace => {
                        self.query.pop();
                    }
                    Key::Enter => self.mode = Mode::Normal,
                    Key::Esc => {
                        self.query.clear();
                        self.mode = Mode::Normal;
                    }
                    other => {
                        self.move_by(other);
                    }
                }
                self.clamp();
                Action::None
            }
            Mode::Normal => {
                self.status.clear();
                match k {
                    Key::Char('k') => self.move_by(Key::Up),
                    Key::Char('j') => self.move_by(Key::Down),
                    Key::Char('g') => self.move_by(Key::Home),
                    Key::Char('G') => self.move_by(Key::End),
                    Key::Char('/') => {
                        self.mode = Mode::Search;
                        true
                    }
                    Key::Char('q') | Key::Esc => return Action::Quit,
                    Key::Char('r') => return Action::Refresh,
                    Key::Enter | Key::Char('c') => {
                        return self.selected().map_or(Action::None, Action::Copy)
                    }
                    Key::Char('d') => {
                        if let Some(n) = self.selected() {
                            self.mode = Mode::Confirm(n);
                        }
                        true
                    }
                    other => self.move_by(other),
                };
                Action::None
            }
        }
    }
}

/// The screen: exactly `h` lines of exactly `w` characters.
pub struct Screen {
    pub lines: Vec<String>,
    /// Index into `lines` of the highlighted row.
    pub selected: Option<usize>,
}

fn fit(s: &str, w: usize) -> String {
    let mut out: String = s.chars().take(w).collect();
    let n = out.chars().count();
    out.extend(std::iter::repeat_n(' ', w - n));
    out
}

pub fn render(st: &State, w: usize, h: usize) -> Screen {
    let vis = st.visible();
    let nw = vis
        .iter()
        .map(|r| r.name.len())
        .max()
        .unwrap_or(0)
        .clamp(4, 32);
    let mut lines = vec![
        format!(
            " kepr ui: {} of {} credentials (values are never shown)",
            vis.len(),
            st.rows.len()
        ),
        format!(
            "  {:<nw$} {:<10} {:<16} {:<14} TAGS",
            "NAME", "TYPE", "EXPIRES", "FLAGS"
        ),
    ];
    let slots = h.saturating_sub(3);
    let offset = st.cursor.saturating_sub(slots.saturating_sub(1));
    let mut selected = None;
    for i in offset..offset + slots {
        let Some(r) = vis.get(i) else {
            lines.push(String::new());
            continue;
        };
        let mark = if i == st.cursor {
            selected = Some(lines.len());
            "> "
        } else {
            "  "
        };
        let flags = if r.flags.is_empty() {
            "-".to_string()
        } else {
            r.flags.join(",")
        };
        lines.push(format!(
            "{mark}{:<nw$} {:<10} {:<16} {:<14} {}",
            r.name,
            r.kind,
            r.expires.as_deref().unwrap_or("-"),
            flags,
            r.tags.join(",")
        ));
    }
    if vis.is_empty() {
        if let Some(l) = lines.get_mut(2) {
            *l = "  (no credentials match)".into();
        }
    }
    lines.push(match &st.mode {
        Mode::Search => format!(" /{}", st.query),
        Mode::Confirm(n) => format!(" delete {n}? y/N"),
        Mode::Normal if !st.status.is_empty() => format!(" {}", st.status),
        Mode::Normal => " j/k move  / search  enter copy  d delete  r reload  q quit".into(),
    });
    lines.truncate(h);
    Screen {
        lines: lines.iter().map(|l| fit(l, w)).collect(),
        selected: selected.filter(|&i| i < h),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(name: &str) -> CredInfo {
        CredInfo {
            name: name.into(),
            cred_name: format!("kepr-1000-{}", name.to_lowercase()),
            size: 40,
            modified: "2026-10-01 12:00".into(),
            ..Default::default()
        }
    }

    fn fixture() -> State {
        let mut gh = info("GITHUB_TOKEN");
        gh.expires_at = Some("2026-12-01 00:00".into());
        gh.requires_consent = Some(true);
        gh.tags = Some(vec!["ci".into(), "team-a".into()]);
        let mut oa = info("OPENAI_API_KEY");
        oa.sealed = Some(true);
        oa.bound_hosts = Some(vec!["api.openai.com".into()]);
        let mut db = info("PROD_DB");
        db.record_type = Some("database".into());
        // Unsorted on purpose: the list sorts by name.
        State::new([db, gh, oa].iter().map(Row::from_info).collect())
    }

    fn trimmed(s: &Screen) -> Vec<&str> {
        s.lines.iter().map(|l| l.trim_end()).collect()
    }

    #[test]
    fn renders_the_fixture_into_a_fixed_buffer() {
        let s = render(&fixture(), 72, 8);
        assert_eq!(
            trimmed(&s),
            vec![
                " kepr ui: 3 of 3 credentials (values are never shown)",
                "  NAME           TYPE       EXPIRES          FLAGS          TAGS",
                "> GITHUB_TOKEN   value      2026-12-01 00:00 consent        ci,team-a",
                "  OPENAI_API_KEY value      -                sealed",
                "  PROD_DB        database   -                -",
                "",
                "",
                " j/k move  / search  enter copy  d delete  r reload  q quit",
            ]
        );
        assert!(s.lines.iter().all(|l| l.chars().count() == 72));
        assert_eq!(s.selected, Some(2));
    }

    #[test]
    fn narrow_and_short_screens_truncate_and_scroll() {
        let mut st = fixture();
        st.key(Key::End);
        let s = render(&st, 20, 5);
        assert_eq!(s.lines.len(), 5);
        assert!(s.lines.iter().all(|l| l.chars().count() == 20));
        // Two row slots: the cursor (last row) stays visible.
        assert_eq!(s.lines[3].trim_end(), "> PROD_DB        dat");
        assert_eq!(s.selected, Some(3));
        assert_eq!(render(&st, 10, 1).lines.len(), 1);
    }

    #[test]
    fn keys_move_search_copy_and_confirm_delete() {
        let mut st = fixture();
        assert_eq!(st.key(Key::Char('j')), Action::None);
        st.key(Key::Down);
        st.key(Key::Down); // clamps at the end
        assert_eq!(st.cursor, 2);
        st.key(Key::Char('k'));
        assert_eq!(st.cursor, 1);

        for k in [Key::Char('/'), Key::Char('d'), Key::Char('b'), Key::Enter] {
            assert_eq!(st.key(k), Action::None);
        }
        assert_eq!(st.query, "db");
        assert_eq!(st.cursor, 0);
        assert_eq!(st.visible().len(), 1);
        assert_eq!(st.key(Key::Enter), Action::Copy("PROD_DB".into()));

        st.key(Key::Char('d'));
        assert_eq!(st.mode, Mode::Confirm("PROD_DB".into()));
        assert_eq!(
            render(&st, 40, 4).lines[3].trim_end(),
            " delete PROD_DB? y/N"
        );
        assert_eq!(st.key(Key::Char('n')), Action::None);
        assert_eq!(st.status, "kept PROD_DB");
        st.key(Key::Char('d'));
        assert_eq!(st.key(Key::Char('y')), Action::Delete("PROD_DB".into()));

        st.key(Key::Char('/'));
        st.key(Key::Esc);
        assert_eq!(st.query, "");
        assert_eq!(st.visible().len(), 3);
        assert_eq!(st.key(Key::Char('r')), Action::Refresh);
        assert_eq!(st.key(Key::Char('q')), Action::Quit);
        assert_eq!(st.key(Key::CtrlC), Action::Quit);
    }

    #[test]
    fn search_typing_q_does_not_quit_and_empty_list_is_safe() {
        let mut st = fixture();
        st.key(Key::Char('/'));
        assert_eq!(st.key(Key::Char('q')), Action::None);
        assert_eq!(st.query, "q");
        st.key(Key::Enter);
        assert_eq!(st.key(Key::Enter), Action::None, "nothing selected");
        assert_eq!(st.key(Key::Char('d')), Action::None);
        assert_eq!(st.mode, Mode::Normal);
        assert_eq!(
            render(&st, 40, 5).lines[2].trim_end(),
            "  (no credentials match)"
        );
        let mut empty = State::new(Vec::new());
        assert_eq!(empty.key(Key::Down), Action::None);
        assert_eq!(empty.cursor, 0);
    }

    #[test]
    fn search_matches_tags() {
        let mut st = fixture();
        for c in ['/', 't', 'e', 'a', 'm'] {
            st.key(Key::Char(c));
        }
        st.key(Key::Enter);
        let names: Vec<&str> = st.visible().iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["GITHUB_TOKEN"]);
    }

    #[test]
    fn rows_carry_no_value_material() {
        let r = Row::from_info(&info("X"));
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("kepr-1000"), "only display metadata is kept");
    }
}
