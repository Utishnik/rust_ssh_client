use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;
//use russh::channels::ChannelMsg::RequestSubsystem; приватный channels
pub struct ReqSubSys {
    pub want_reply: bool,
    pub name: Arc<str>, //
}

impl ReqSubSys {
    pub fn new(want_reply: bool, name: Arc<str>) -> Self {
        Self { want_reply, name }
    }
}

pub struct ChannelSetEnv {
    pub want_reply: bool,
    pub variable_name: String,
    pub variable_value: String,
}

static CHANNEL_SET_ENV: OnceLock<Arc<RwLock<Vec<ChannelSetEnv>>>> = OnceLock::new();
static CHANNEL_SET_ENV_WITH_VEC_CAP: usize = 128;

pub fn add_channel_env(value: ChannelSetEnv) {
    //let get = CHANNEL_SET_ENV.get_mut_or_init(|| Arc::new(RwLock::new(Vec::new())));
    let get: &Arc<RwLock<Vec<ChannelSetEnv>>> = CHANNEL_SET_ENV.get_or_init(|| {
        Arc::new(RwLock::new(Vec::with_capacity(
            CHANNEL_SET_ENV_WITH_VEC_CAP,
        )))
    });
    let guard: Result<
        std::sync::RwLockWriteGuard<'_, Vec<ChannelSetEnv>>,
        std::sync::PoisonError<std::sync::RwLockWriteGuard<'_, Vec<ChannelSetEnv>>>,
    > = get.write();
    if guard.is_err() {
        println!("add_channel_env PoisonError");
        return;
    }
    let mut unwrap_guard: std::sync::RwLockWriteGuard<'_, Vec<ChannelSetEnv>> = guard.unwrap();
    unwrap_guard.push(value);
}
