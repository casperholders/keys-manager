#![no_main]
#![no_std]

extern crate alloc;

use alloc::{vec::Vec};

use casper_contract::{
    contract_api::{account, runtime},
    unwrap_or_revert::UnwrapOrRevert,
};
use casper_types::{account::{
    AccountHash, ActionType, AddKeyFailure, RemoveKeyFailure, SetThresholdFailure,
    UpdateKeyFailure, Weight,
}, ApiError};

mod errors;
use errors::Error;

pub const ARG_ACCOUNTS: &str = "accounts";
pub const ARG_WEIGHTS: &str = "weights";
pub const ARG_DEPLOYMENT_THRESHOLD: &str = "deployment_threshold";
pub const ARG_KEY_MANAGEMENT_THRESHOLD: &str = "key_management_threshold";

#[no_mangle]
pub extern "C" fn call() {
    let deployment_threshold_arg:Option<u8> = runtime::get_named_arg(ARG_DEPLOYMENT_THRESHOLD);
    let key_management_threshold_arg:Option<u8>  = runtime::get_named_arg(ARG_KEY_MANAGEMENT_THRESHOLD);
    let accounts_arg:Option<Vec<AccountHash>>  = runtime::get_named_arg(ARG_ACCOUNTS);
    let weights_arg:Option<Vec<Weight>>  = runtime::get_named_arg(ARG_WEIGHTS);

    if deployment_threshold_arg == None && key_management_threshold_arg == None && (accounts_arg == None || weights_arg == None) {
        runtime::revert(ApiError::MissingArgument)
    }

    if accounts_arg.is_some() && weights_arg.is_some() {
        let accounts: Vec<AccountHash> = accounts_arg.unwrap();
        let weights: Vec<Weight> = weights_arg.unwrap();

        for (account, weight) in accounts.into_iter().zip(weights) {
            update_key_weight(account, weight);
        }
    }

    if deployment_threshold_arg.is_some() {
        let deployment_threshold: Weight =
            Weight::new(deployment_threshold_arg.unwrap());
        set_threshold(ActionType::Deployment, deployment_threshold).unwrap_or_revert();
    }

    if key_management_threshold_arg.is_some() {
        let key_management_threshold: Weight =
            Weight::new(key_management_threshold_arg.unwrap());
        set_threshold(ActionType::KeyManagement, key_management_threshold).unwrap_or_revert();
    }
}

fn update_key_weight(account: AccountHash, weight: Weight) {
    if weight.value() == 0 {
        remove_key_if_exists(account).unwrap_or_revert()
    } else {
        add_or_update_key(account, weight).unwrap_or_revert()
    }
}

fn set_threshold(permission_level: ActionType, threshold: Weight) -> Result<(), Error> {
    match account::set_action_threshold(permission_level, threshold) {
        Ok(()) => Ok(()),
        Err(SetThresholdFailure::KeyManagementThreshold) => Err(Error::KeyManagementThreshold),
        Err(SetThresholdFailure::DeploymentThreshold) => Err(Error::DeploymentThreshold),
        Err(SetThresholdFailure::PermissionDeniedError) => Err(Error::PermissionDenied),
        Err(SetThresholdFailure::InsufficientTotalWeight) => Err(Error::InsufficientTotalWeight),
    }
}

fn add_or_update_key(key: AccountHash, weight: Weight) -> Result<(), Error> {
    match account::update_associated_key(key, weight) {
        Ok(()) => Ok(()),
        Err(UpdateKeyFailure::MissingKey) => add_key(key, weight),
        Err(UpdateKeyFailure::PermissionDenied) => Err(Error::PermissionDenied),
        Err(UpdateKeyFailure::ThresholdViolation) => Err(Error::ThresholdViolation),
    }
}

fn add_key(key: AccountHash, weight: Weight) -> Result<(), Error> {
    match account::add_associated_key(key, weight) {
        Ok(()) => Ok(()),
        Err(AddKeyFailure::MaxKeysLimit) => Err(Error::MaxKeysLimit),
        Err(AddKeyFailure::DuplicateKey) => Err(Error::DuplicateKey), // Should never happen.
        Err(AddKeyFailure::PermissionDenied) => Err(Error::PermissionDenied),
    }
}

fn remove_key_if_exists(key: AccountHash) -> Result<(), Error> {
    match account::remove_associated_key(key) {
        Ok(()) => Ok(()),
        Err(RemoveKeyFailure::MissingKey) => Ok(()),
        Err(RemoveKeyFailure::PermissionDenied) => Err(Error::PermissionDenied),
        Err(RemoveKeyFailure::ThresholdViolation) => Err(Error::ThresholdViolation),
    }
}
