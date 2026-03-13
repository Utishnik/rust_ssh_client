use russh::keys;

#[derive(Default)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: Option<u32>,
}

impl Output {
    pub fn stdout_string(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into()
    }

    pub fn stderr_string(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into()
    }

    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}
