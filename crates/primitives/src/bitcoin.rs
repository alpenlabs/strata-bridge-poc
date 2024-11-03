use bitcoin::{address::NetworkUnchecked, Address, Network};
use serde::{de, Deserialize, Deserializer, Serialize};

/// A wrapper around the [`bitcoin::Address<NetworkChecked>`] type created in order to implement
/// some useful traits on it such as [`serde::Deserialize`], [`borsh::BorshSerialize`] and
/// [`borsh::BorshDeserialize`].
// TODO: implement [`arbitrary::Arbitrary`]?
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BitcoinAddress {
    /// The [`bitcoin::Network`] that this address is valid in.
    network: Network,

    /// The actual [`Address`] that this type wraps.
    address: Address,
}

impl BitcoinAddress {
    pub fn parse(address_str: &str, network: Network) -> anyhow::Result<Self> {
        let address = address_str.parse::<Address<NetworkUnchecked>>()?;

        let checked_address = address.require_network(network)?;

        Ok(Self {
            network,
            address: checked_address,
        })
    }
}

impl BitcoinAddress {
    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn network(&self) -> &Network {
        &self.network
    }
}

impl<'de> Deserialize<'de> for BitcoinAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct BitcoinAddressShim {
            network: Network,
            address: String,
        }

        let shim = BitcoinAddressShim::deserialize(deserializer)?;
        let address = shim
            .address
            .parse::<Address<NetworkUnchecked>>()
            .map_err(|_| de::Error::custom("invalid bitcoin address"))?
            .require_network(shim.network)
            .map_err(|_| de::Error::custom("address invalid for given network"))?;

        Ok(BitcoinAddress {
            network: shim.network,
            address,
        })
    }
}
