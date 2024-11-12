pub const DEFAULT_RPC_HOST: &str = "127.0.0.1";
pub const DEFAULT_RPC_PORT: u32 = 4781;

pub const DUTY_QUEUE_SIZE: usize = 5; // probably overkill
pub const DEPOSIT_QUEUE_MULTIPLIER: usize = 2;
pub const COVENANT_QUEUE_MULTIPLIER: usize = 10;

pub const VERIFIER_DUTY_QUEUE_SIZE: usize = 20; // only one verifier so needs a lot of buffer

pub const DEFAULT_NUM_THREADS: usize = 3;
pub const DEFAULT_STACK_SIZE_MB: usize = 512;

pub const PUBLIC_DB_NAME: &str = "public.db";
pub const DUTY_TRACKER_DB_NAME: &str = "duty_tracker.db";
pub const BITCOIN_BLOCK_TRACKER_DB_NAME: &str = "btc_block_tracker.db";
pub const OPERATOR_DB_PREFIX: &str = "operator_";
