use std::error::Error;
use std::fmt;

use zbus::{
    dbus_interface,
    zvariant::{ObjectPath, Value},
};

/// Network technology types supported by ConnMan
#[derive(Debug, Clone, Copy)]
pub enum NetworkTechnology {
    Ethernet,
    Wifi,
    Cellular,
    Bluetooth,
    Unknown,
}

/// Network connection state
#[derive(Debug, Clone, Copy)]
pub enum NetworkState {
    Online,
    Ready,
    Offline,
    Unknown,
}

/// ConnMan network manager interface
#[derive(Debug)]
pub struct ConnManManager {
    connection: zbus::Connection,
    manager_proxy: zbus::Proxy<'static>,
}

impl ConnManManager {
    /// Create a new ConnMan manager connection
    pub async fn new() -> Result<Self, Box<dyn Error>> {
        let connection = zbus::Connection::system().await?;
        let manager_proxy = zbus::Proxy::new(
            &connection,
            "net.connman",
            "/",
            "net.connman.Manager",
        )
        .await?;

        Ok(Self {
            connection,
            manager_proxy,
        })
    }

    /// Get current network state
    pub async fn get_state(&self) -> Result<NetworkState, Box<dyn Error>> {
        let state: String = self.manager_proxy.get_property("State").await?;
        Ok(match state.as_str() {
            "online" => NetworkState::Online,
            "ready" => NetworkState::Ready,
            "offline" => NetworkState::Offline,
            _ => NetworkState::Unknown,
        })
    }

    /// Get available network technologies
    pub async fn get_technologies(&self) -> Result<Vec<NetworkTechnology>, Box<dyn Error>> {
        let technologies: Vec<Value> = self.manager_proxy.call_method("GetTechnologies", &()).await?.body()?;

        let mut techs = Vec::new();
        for tech in technologies {
            if let Value::ObjectPath(path) = tech {
                let tech_proxy = zbus::Proxy::new(
                    &self.connection,
                    "net.connman",
                    &ObjectPath::from(path),
                    "net.connman.Technology",
                )
                .await?;

                let type_str: String = tech_proxy.get_property("Type").await?;
                techs.push(match type_str.as_str() {
                    "ethernet" => NetworkTechnology::Ethernet,
                    "wifi" => NetworkTechnology::Wifi,
                    "cellular" => NetworkTechnology::Cellular,
                    "bluetooth" => NetworkTechnology::Bluetooth,
                    _ => NetworkTechnology::Unknown,
                });
            }
        }

        Ok(techs)
    }

    /// Get list of available services
    pub async fn get_services(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let services: Vec<Value> = self.manager_proxy.call_method("GetServices", &()).await?.body()?;
        let mut service_names = Vec::new();

        for service in services {
            if let Value::ObjectPath(path) = service {
                let service_proxy = zbus::Proxy::new(
                    &self.connection,
                    "net.connman",
                    &ObjectPath::from(path),
                    "net.connman.Service",
                )
                .await?;

                if let Ok(name) = service_proxy.get_property::<String>("Name").await {
                    service_names.push(name);
                }
            }
        }

        Ok(service_names)
    }

    /// Connect to a specific service
    pub async fn connect_service(&self, service_name: &str) -> Result<(), Box<dyn Error>> {
        let services = self.get_services().await?;

        for service in services {
            if service == service_name {
                let service_path = self.find_service_path(&service).await?;
                let service_proxy = zbus::Proxy::new(
                    &self.connection,
                    "net.connman",
                    &ObjectPath::from(service_path),
                    "net.connman.Service",
                )
                .await?;

                service_proxy.call_method("Connect", &()).await?;
                return Ok(());
            }
        }

        Err("Service not found".into())
    }

    async fn find_service_path(&self, service_name: &str) -> Result<ObjectPath<'static>, Box<dyn Error>> {
        let services: Vec<Value> = self.manager_proxy.call_method("GetServices", &()).await?.body()?;

        for service in services {
            if let Value::ObjectPath(path) = service {
                let service_proxy = zbus::Proxy::new(
                    &self.connection,
                    "net.connman",
                    &ObjectPath::from(path.clone()),
                    "net.connman.Service",
                )
                .await?;

                if let Ok(name) = service_proxy.get_property::<String>("Name").await {
                    if name == service_name {
                        return Ok(path);
                    }
                }
            }
        }

        Err("Service path not found".into())
    }
}

/// ConnMan network service interface
#[dbus_interface(name = "net.connman.Service")]
trait ConnManService {
    /// Connect to the service
    async fn connect(&mut self) -> Result<(), Box<dyn Error>>;

    /// Disconnect from the service
    async fn disconnect(&mut self) -> Result<(), Box<dyn Error>>;

    /// Get service properties
    async fn get_properties(&self) -> Result<Vec<(String, Value)>, Box<dyn Error>>;
}

/// Error type for network operations
#[derive(Debug)]
pub struct NetworkError {
    details: String,
}

impl NetworkError {
    pub fn new(msg: &str) -> Self {
        NetworkError {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Network error: {}", self.details)
    }
}

impl Error for NetworkError {}