#[macro_export]
macro_rules! repeat {
    ($times:expr, $body:expr) => {
        for _ in 0..($times) {
            $body
        }
    };
}

#[macro_export]
macro_rules! return_unless {
    ($cond:expr) => {
        if !($cond) {
            return;
        }
    };
    ($cond:expr, $val:expr) => {
        if !($cond) {
            return $val;
        }
    };
}

#[macro_export]
macro_rules! return_if {
    ($cond:expr) => {
        if $cond {
            return;
        }
    };
    ($cond:expr, $val:expr) => {
        if $cond {
            return $val;
        }
    };
}

#[macro_export]
macro_rules! break_if {
    ($cond:expr) => {
        if $cond {
            break;
        }
    };
    ($cond:expr, $val:expr) => {
        if $cond {
            break $val;
        }
    };
}

#[macro_export]
macro_rules! continue_if {
    ($cond:expr) => {
        if $cond {
            continue;
        }
    };
    ($cond:expr, $val:expr) => {
        if $cond {
            break $val;
        }
    };
}
