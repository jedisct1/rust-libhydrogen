use core::{
    convert::TryFrom,
    fmt,
    mem::{size_of_val, MaybeUninit},
    ptr,
};

use super::ensure_initialized;
use crate::{errors::*, ffi, random, utils};

pub const PUBLICKEYBYTES: usize = ffi::hydro_kx_PUBLICKEYBYTES as usize;
pub const SECRETKEYBYTES: usize = ffi::hydro_kx_SECRETKEYBYTES as usize;
pub const SESSIONKEYBYTES: usize = ffi::hydro_kx_SESSIONKEYBYTES as usize;
pub const SEEDBYTES: usize = ffi::hydro_kx_SEEDBYTES as usize;
pub const PSKBYTES: usize = ffi::hydro_kx_PSKBYTES as usize;
pub const N_PACKET1BYTES: usize = ffi::hydro_kx_N_PACKET1BYTES as usize;
pub const KK_PACKET1BYTES: usize = ffi::hydro_kx_KK_PACKET1BYTES as usize;
pub const KK_PACKET2BYTES: usize = ffi::hydro_kx_KK_PACKET2BYTES as usize;
pub const NK_PACKET1BYTES: usize = ffi::hydro_kx_NK_PACKET1BYTES as usize;
pub const NK_PACKET2BYTES: usize = ffi::hydro_kx_NK_PACKET2BYTES as usize;
pub const XX_PACKET1BYTES: usize = ffi::hydro_kx_XX_PACKET1BYTES as usize;
pub const XX_PACKET2BYTES: usize = ffi::hydro_kx_XX_PACKET2BYTES as usize;
pub const XX_PACKET3BYTES: usize = ffi::hydro_kx_XX_PACKET3BYTES as usize;

#[derive(Debug, Copy, PartialEq, Eq, Clone)]
pub struct PublicKey([u8; PUBLICKEYBYTES]);

#[derive(Clone)]
pub struct SecretKey([u8; SECRETKEYBYTES]);

#[derive(Debug, Clone)]
pub struct Seed([u8; SEEDBYTES]);

#[derive(Clone)]
pub struct Psk([u8; PSKBYTES]);

#[derive(Clone)]
pub struct NPacket1([u8; N_PACKET1BYTES]);

#[derive(Clone)]
pub struct KKPacket1([u8; KK_PACKET1BYTES]);

#[derive(Clone)]
pub struct KKPacket2([u8; KK_PACKET2BYTES]);

#[derive(Clone)]
pub struct NKPacket1([u8; NK_PACKET1BYTES]);

#[derive(Clone)]
pub struct NKPacket2([u8; NK_PACKET2BYTES]);

#[derive(Clone)]
pub struct XXPacket1([u8; XX_PACKET1BYTES]);

#[derive(Clone)]
pub struct XXPacket2([u8; XX_PACKET2BYTES]);

#[derive(Clone)]
pub struct XXPacket3([u8; XX_PACKET3BYTES]);

#[derive(Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

#[derive(Clone)]
pub struct SessionKey([u8; SESSIONKEYBYTES]);

#[derive(Clone)]
#[repr(C)]
pub struct SessionKeyPair {
    pub rx: SessionKey,
    pub tx: SessionKey,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct State(ffi::hydro_kx_state);

pub fn n_1(
    npacket1: &mut NPacket1,
    psk: Option<&Psk>,
    server_static_keypair_public_key: &PublicKey,
) -> Result<SessionKeyPair, HydroError> {
    ensure_initialized();
    let psk = match psk {
        None => ptr::null(),
        Some(psk) => psk.0.as_ptr(),
    };
    unsafe {
        let mut session_keypair_c = MaybeUninit::<ffi::hydro_kx_session_keypair>::uninit();
        if ffi::hydro_kx_n_1(
            session_keypair_c.as_mut_ptr(),
            npacket1.0.as_mut_ptr(),
            psk,
            server_static_keypair_public_key.0.as_ptr(),
        ) != 0
        {
            Err(HydroError::InvalidInput)
        } else {
            Ok(SessionKeyPair::from(session_keypair_c))
        }
    }
}

pub fn n_2(
    npacket1: &NPacket1,
    psk: Option<&Psk>,
    server_static_keypair: &KeyPair,
) -> Result<SessionKeyPair, HydroError> {
    ensure_initialized();
    let psk = match psk {
        None => ptr::null(),
        Some(psk) => psk.0.as_ptr(),
    };
    unsafe {
        let mut session_keypair_c = MaybeUninit::<ffi::hydro_kx_session_keypair>::uninit();
        if ffi::hydro_kx_n_2(
            session_keypair_c.as_mut_ptr(),
            npacket1.0.as_ptr(),
            psk,
            server_static_keypair as *const _ as *const _,
        ) != 0
        {
            Err(HydroError::InvalidInput)
        } else {
            Ok(SessionKeyPair::from(session_keypair_c))
        }
    }
}

pub fn kk_1(
    client_state: &mut State,
    kkpacket1: &mut KKPacket1,
    server_static_keypair_public_key: &PublicKey,
    client_static_keypair: &KeyPair,
) -> Result<(), HydroError> {
    ensure_initialized();
    unsafe {
        if ffi::hydro_kx_kk_1(
            client_state as *mut _ as *mut _,
            kkpacket1.0.as_mut_ptr(),
            server_static_keypair_public_key.0.as_ptr(),
            client_static_keypair as *const _ as *const _,
        ) != 0
        {
            Err(HydroError::InvalidInput)
        } else {
            Ok(())
        }
    }
}

pub fn kk_2(
    kkpacket2: &mut KKPacket2,
    kkpacket1: &KKPacket1,
    client_static_keypair_public_key: &PublicKey,
    server_static_keypair: &KeyPair,
) -> Result<SessionKeyPair, HydroError> {
    ensure_initialized();
    unsafe {
        let mut session_keypair_c = MaybeUninit::<ffi::hydro_kx_session_keypair>::uninit();
        if ffi::hydro_kx_kk_2(
            session_keypair_c.as_mut_ptr(),
            kkpacket2.0.as_mut_ptr(),
            kkpacket1.0.as_ptr(),
            client_static_keypair_public_key.0.as_ptr(),
            server_static_keypair as *const _ as *const _,
        ) != 0
        {
            Err(HydroError::InvalidInput)
        } else {
            Ok(SessionKeyPair::from(session_keypair_c))
        }
    }
}

pub fn kk_3(
    client_state: &mut State,
    kkpacket2: &KKPacket2,
    client_static_keypair: &KeyPair,
) -> Result<SessionKeyPair, HydroError> {
    ensure_initialized();
    unsafe {
        let mut session_keypair_c = MaybeUninit::<ffi::hydro_kx_session_keypair>::uninit();
        if ffi::hydro_kx_kk_3(
            client_state as *mut _ as *mut _,
            session_keypair_c.as_mut_ptr(),
            kkpacket2.0.as_ptr(),
            client_static_keypair as *const _ as *const _,
        ) != 0
        {
            Err(HydroError::InvalidInput)
        } else {
            Ok(SessionKeyPair::from(session_keypair_c))
        }
    }
}

pub fn nk_1(
    client_state: &mut State,
    nkpacket1: &mut NKPacket1,
    psk: Option<&Psk>,
    server_static_keypair_public_key: &PublicKey,
) -> Result<(), HydroError> {
    ensure_initialized();
    let psk = match psk {
        None => ptr::null(),
        Some(psk) => psk.0.as_ptr(),
    };
    unsafe {
        if ffi::hydro_kx_nk_1(
            client_state as *mut _ as *mut _,
            nkpacket1.0.as_mut_ptr(),
            psk,
            server_static_keypair_public_key.0.as_ptr(),
        ) != 0
        {
            Err(HydroError::InvalidInput)
        } else {
            Ok(())
        }
    }
}

pub fn nk_2(
    nkpacket2: &mut NKPacket2,
    nkpacket1: &NKPacket1,
    psk: Option<&Psk>,
    server_static_keypair: &KeyPair,
) -> Result<SessionKeyPair, HydroError> {
    ensure_initialized();
    let psk = match psk {
        None => ptr::null(),
        Some(psk) => psk.0.as_ptr(),
    };
    unsafe {
        let mut session_keypair_c = MaybeUninit::<ffi::hydro_kx_session_keypair>::uninit();
        if ffi::hydro_kx_nk_2(
            session_keypair_c.as_mut_ptr(),
            nkpacket2.0.as_mut_ptr(),
            nkpacket1.0.as_ptr(),
            psk,
            server_static_keypair as *const _ as *const _,
        ) != 0
        {
            Err(HydroError::InvalidInput)
        } else {
            Ok(SessionKeyPair::from(session_keypair_c))
        }
    }
}

pub fn nk_3(client_state: &mut State, nkpacket2: &NKPacket2) -> Result<SessionKeyPair, HydroError> {
    ensure_initialized();
    unsafe {
        let mut session_keypair_c = MaybeUninit::<ffi::hydro_kx_session_keypair>::uninit();
        if ffi::hydro_kx_nk_3(
            client_state as *mut _ as *mut _,
            session_keypair_c.as_mut_ptr(),
            nkpacket2.0.as_ptr(),
        ) != 0
        {
            Err(HydroError::InvalidInput)
        } else {
            Ok(SessionKeyPair::from(session_keypair_c))
        }
    }
}

pub fn xx_1(
    client_state: &mut State,
    xxpacket1: &mut XXPacket1,
    psk: Option<&Psk>,
) -> Result<(), HydroError> {
    ensure_initialized();
    let psk = match psk {
        None => ptr::null(),
        Some(psk) => psk.0.as_ptr(),
    };
    unsafe {
        if ffi::hydro_kx_xx_1(
            client_state as *mut _ as *mut _,
            xxpacket1.0.as_mut_ptr(),
            psk,
        ) != 0
        {
            Err(HydroError::InvalidInput)
        } else {
            Ok(())
        }
    }
}

pub fn xx_2(
    server_state: &mut State,
    xxpacket2: &mut XXPacket2,
    xxpacket1: &XXPacket1,
    psk: Option<&Psk>,
    server_static_keypair: &KeyPair,
) -> Result<(), HydroError> {
    ensure_initialized();
    let psk = match psk {
        None => ptr::null(),
        Some(psk) => psk.0.as_ptr(),
    };
    unsafe {
        if ffi::hydro_kx_xx_2(
            server_state as *mut _ as *mut _,
            xxpacket2.0.as_mut_ptr(),
            xxpacket1.0.as_ptr(),
            psk,
            server_static_keypair as *const _ as *const _,
        ) != 0
        {
            Err(HydroError::InvalidInput)
        } else {
            Ok(())
        }
    }
}

pub fn xx_3(
    client_state: &mut State,
    xxpacket3: &mut XXPacket3,
    peer_static_public_key: Option<&mut PublicKey>,
    xxpacket2: &XXPacket2,
    psk: Option<&Psk>,
    client_static_keypair: &KeyPair,
) -> Result<SessionKeyPair, HydroError> {
    ensure_initialized();
    let psk = match psk {
        None => ptr::null(),
        Some(psk) => psk.0.as_ptr(),
    };
    let peer_static_public_key = match peer_static_public_key {
        None => ptr::null(),
        Some(peer_static_public_key) => peer_static_public_key.0.as_mut_ptr(),
    };
    unsafe {
        let mut session_keypair_c = MaybeUninit::<ffi::hydro_kx_session_keypair>::uninit();
        if ffi::hydro_kx_xx_3(
            client_state as *mut _ as *mut _,
            session_keypair_c.as_mut_ptr(),
            xxpacket3.0.as_mut_ptr(),
            peer_static_public_key as *mut _,
            xxpacket2.0.as_ptr(),
            psk,
            client_static_keypair as *const _ as *const _,
        ) != 0
        {
            Err(HydroError::InvalidInput)
        } else {
            Ok(SessionKeyPair::from(session_keypair_c))
        }
    }
}

pub fn xx_4(
    server_state: &mut State,
    peer_static_public_key: Option<&mut PublicKey>,
    xxpacket3: &XXPacket3,
    psk: Option<&Psk>,
) -> Result<SessionKeyPair, HydroError> {
    ensure_initialized();
    let psk = match psk {
        None => ptr::null(),
        Some(psk) => psk.0.as_ptr(),
    };
    let peer_static_public_key = match peer_static_public_key {
        None => ptr::null(),
        Some(peer_static_public_key) => peer_static_public_key.0.as_mut_ptr(),
    };
    unsafe {
        let mut session_keypair_c = MaybeUninit::<ffi::hydro_kx_session_keypair>::uninit();
        if ffi::hydro_kx_xx_4(
            server_state as *mut _ as *mut _,
            session_keypair_c.as_mut_ptr(),
            peer_static_public_key as *mut _,
            xxpacket3.0.as_ptr(),
            psk,
        ) != 0
        {
            Err(HydroError::InvalidInput)
        } else {
            Ok(SessionKeyPair::from(session_keypair_c))
        }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        utils::memzero(self)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        utils::memzero(self)
    }
}

impl From<[u8; SECRETKEYBYTES]> for SecretKey {
    #[inline]
    fn from(key: [u8; SECRETKEYBYTES]) -> SecretKey {
        SecretKey(key)
    }
}

impl Into<[u8; SECRETKEYBYTES]> for SecretKey {
    #[inline]
    fn into(self) -> [u8; SECRETKEYBYTES] {
        self.0
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        utils::equal(self, other)
    }
}

impl Eq for SecretKey {}

impl From<[u8; PUBLICKEYBYTES]> for PublicKey {
    #[inline]
    fn from(key: [u8; PUBLICKEYBYTES]) -> PublicKey {
        PublicKey(key)
    }
}

impl Into<[u8; PUBLICKEYBYTES]> for PublicKey {
    #[inline]
    fn into(self) -> [u8; PUBLICKEYBYTES] {
        self.0
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        utils::memzero(self)
    }
}

impl From<[u8; SEEDBYTES]> for Seed {
    #[inline]
    fn from(seed: [u8; SEEDBYTES]) -> Seed {
        Seed(seed)
    }
}

impl Into<[u8; SEEDBYTES]> for Seed {
    #[inline]
    fn into(self) -> [u8; SEEDBYTES] {
        self.0
    }
}

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl PartialEq for Seed {
    fn eq(&self, other: &Self) -> bool {
        utils::equal(self, other)
    }
}

impl Eq for Seed {}

impl From<[u8; PSKBYTES]> for Psk {
    #[inline]
    fn from(key: [u8; PSKBYTES]) -> Psk {
        Psk(key)
    }
}

impl Into<[u8; PSKBYTES]> for Psk {
    #[inline]
    fn into(self) -> [u8; PSKBYTES] {
        self.0
    }
}

impl AsRef<[u8]> for Psk {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl TryFrom<&'static str> for Psk {
    type Error = HydroError;

    fn try_from(psk_str: &'static str) -> Result<Psk, HydroError> {
        let psk_str_u8 = psk_str.as_bytes();
        if psk_str_u8.len() != PSKBYTES {
            Err(HydroError::InvalidInput)
        } else {
            let mut arr: [u8; PSKBYTES] = [0u8; PSKBYTES];
            arr.copy_from_slice(&psk_str_u8[..PSKBYTES]);
            Ok(Psk::from(arr))
        }
    }
}

impl From<[u8; N_PACKET1BYTES]> for NPacket1 {
    #[inline]
    fn from(npacket1: [u8; N_PACKET1BYTES]) -> NPacket1 {
        NPacket1(npacket1)
    }
}

impl Into<[u8; N_PACKET1BYTES]> for NPacket1 {
    #[inline]
    fn into(self) -> [u8; N_PACKET1BYTES] {
        self.0
    }
}

impl AsRef<[u8]> for NPacket1 {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl From<[u8; KK_PACKET1BYTES]> for KKPacket1 {
    #[inline]
    fn from(kkpacket1: [u8; KK_PACKET1BYTES]) -> KKPacket1 {
        KKPacket1(kkpacket1)
    }
}

impl Into<[u8; KK_PACKET1BYTES]> for KKPacket1 {
    #[inline]
    fn into(self) -> [u8; KK_PACKET1BYTES] {
        self.0
    }
}

impl AsRef<[u8]> for KKPacket1 {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl From<[u8; KK_PACKET2BYTES]> for KKPacket2 {
    #[inline]
    fn from(kkpacket2: [u8; KK_PACKET2BYTES]) -> KKPacket2 {
        KKPacket2(kkpacket2)
    }
}

impl Into<[u8; KK_PACKET2BYTES]> for KKPacket2 {
    #[inline]
    fn into(self) -> [u8; KK_PACKET2BYTES] {
        self.0
    }
}

impl AsRef<[u8]> for KKPacket2 {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl From<[u8; NK_PACKET1BYTES]> for NKPacket1 {
    #[inline]
    fn from(nkpacket1: [u8; NK_PACKET1BYTES]) -> NKPacket1 {
        NKPacket1(nkpacket1)
    }
}

impl Into<[u8; NK_PACKET1BYTES]> for NKPacket1 {
    #[inline]
    fn into(self) -> [u8; NK_PACKET1BYTES] {
        self.0
    }
}

impl AsRef<[u8]> for NKPacket1 {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl From<[u8; NK_PACKET2BYTES]> for NKPacket2 {
    #[inline]
    fn from(nkpacket2: [u8; NK_PACKET2BYTES]) -> NKPacket2 {
        NKPacket2(nkpacket2)
    }
}

impl Into<[u8; NK_PACKET2BYTES]> for NKPacket2 {
    #[inline]
    fn into(self) -> [u8; NK_PACKET2BYTES] {
        self.0
    }
}

impl AsRef<[u8]> for NKPacket2 {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl From<[u8; XX_PACKET1BYTES]> for XXPacket1 {
    #[inline]
    fn from(xxpacket1: [u8; XX_PACKET1BYTES]) -> XXPacket1 {
        XXPacket1(xxpacket1)
    }
}

impl Into<[u8; XX_PACKET1BYTES]> for XXPacket1 {
    #[inline]
    fn into(self) -> [u8; XX_PACKET1BYTES] {
        self.0
    }
}

impl AsRef<[u8]> for XXPacket1 {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl From<[u8; XX_PACKET2BYTES]> for XXPacket2 {
    #[inline]
    fn from(xxpacket2: [u8; XX_PACKET2BYTES]) -> XXPacket2 {
        XXPacket2(xxpacket2)
    }
}

impl Into<[u8; XX_PACKET2BYTES]> for XXPacket2 {
    #[inline]
    fn into(self) -> [u8; XX_PACKET2BYTES] {
        self.0
    }
}

impl AsRef<[u8]> for XXPacket2 {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl From<[u8; XX_PACKET3BYTES]> for XXPacket3 {
    #[inline]
    fn from(xxpacket3: [u8; XX_PACKET3BYTES]) -> XXPacket3 {
        XXPacket3(xxpacket3)
    }
}

impl Into<[u8; XX_PACKET3BYTES]> for XXPacket3 {
    #[inline]
    fn into(self) -> [u8; XX_PACKET3BYTES] {
        self.0
    }
}

impl AsRef<[u8]> for XXPacket3 {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        utils::memzero(self)
    }
}

impl From<[u8; SESSIONKEYBYTES]> for SessionKey {
    #[inline]
    fn from(key: [u8; SESSIONKEYBYTES]) -> SessionKey {
        SessionKey(key)
    }
}

impl Into<[u8; SESSIONKEYBYTES]> for SessionKey {
    #[inline]
    fn into(self) -> [u8; SESSIONKEYBYTES] {
        self.0
    }
}

impl AsRef<[u8]> for SessionKey {
    fn as_ref(&self) -> &[u8] {
        &self.0 as &[u8]
    }
}

impl PartialEq for SessionKey {
    fn eq(&self, other: &Self) -> bool {
        utils::equal(self, other)
    }
}

impl Eq for SessionKey {}

impl fmt::Debug for NPacket1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_tuple("NPacket1");
        for byte in self.as_ref().iter() {
            builder.field(byte);
        }
        builder.finish()
    }
}

impl fmt::Debug for KKPacket1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_tuple("KKPacket1");
        for byte in self.as_ref().iter() {
            builder.field(byte);
        }
        builder.finish()
    }
}

impl fmt::Debug for KKPacket2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_tuple("KKPacket2");
        for byte in self.as_ref().iter() {
            builder.field(byte);
        }
        builder.finish()
    }
}

impl fmt::Debug for NKPacket1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_tuple("NKPacket1");
        for byte in self.as_ref().iter() {
            builder.field(byte);
        }
        builder.finish()
    }
}

impl fmt::Debug for NKPacket2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_tuple("NKPacket2");
        for byte in self.as_ref().iter() {
            builder.field(byte);
        }
        builder.finish()
    }
}

impl fmt::Debug for XXPacket1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_tuple("XXPacket1");
        for byte in self.as_ref().iter() {
            builder.field(byte);
        }
        builder.finish()
    }
}

impl fmt::Debug for XXPacket2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_tuple("XXPacket2");
        for byte in self.as_ref().iter() {
            builder.field(byte);
        }
        builder.finish()
    }
}

impl fmt::Debug for XXPacket3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_tuple("XXPacket3");
        for byte in self.as_ref().iter() {
            builder.field(byte);
        }
        builder.finish()
    }
}

impl From<MaybeUninit<ffi::hydro_kx_keypair>> for KeyPair {
    fn from(keypair_c: MaybeUninit<ffi::hydro_kx_keypair>) -> KeyPair {
        unsafe {
            let mut keypair_c = keypair_c.assume_init();
            let mut keypair = MaybeUninit::<KeyPair>::uninit();
            (*keypair.as_mut_ptr())
                .public_key
                .0
                .copy_from_slice(&keypair_c.pk);
            (*keypair.as_mut_ptr())
                .secret_key
                .0
                .copy_from_slice(&keypair_c.sk);
            ffi::hydro_memzero(&mut keypair_c as *mut _ as *mut _, size_of_val(&keypair_c));
            keypair.assume_init()
        }
    }
}

impl From<MaybeUninit<ffi::hydro_kx_session_keypair>> for SessionKeyPair {
    fn from(session_keypair_c: MaybeUninit<ffi::hydro_kx_session_keypair>) -> SessionKeyPair {
        unsafe {
            let mut session_keypair_c = session_keypair_c.assume_init();
            let mut session_keypair = MaybeUninit::<SessionKeyPair>::uninit();
            (*session_keypair.as_mut_ptr())
                .tx
                .0
                .copy_from_slice(&session_keypair_c.tx);
            (*session_keypair.as_mut_ptr())
                .rx
                .0
                .copy_from_slice(&session_keypair_c.rx);
            ffi::hydro_memzero(
                &mut session_keypair_c as *mut _ as *mut _,
                size_of_val(&session_keypair_c),
            );
            session_keypair.assume_init()
        }
    }
}

impl Seed {
    pub fn gen() -> Seed {
        let mut seed_inner = [0u8; SEEDBYTES];
        random::buf_into(&mut seed_inner);
        Seed(seed_inner)
    }
}

impl State {
    pub fn new() -> State {
        unsafe { MaybeUninit::<State>::zeroed().assume_init() }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl NPacket1 {
    pub fn new() -> NPacket1 {
        NPacket1::from([0u8; N_PACKET1BYTES])
    }
}

impl Default for NPacket1 {
    fn default() -> Self {
        Self::new()
    }
}

impl KKPacket1 {
    pub fn new() -> KKPacket1 {
        KKPacket1::from([0u8; KK_PACKET1BYTES])
    }
}

impl Default for KKPacket1 {
    fn default() -> Self {
        Self::new()
    }
}

impl KKPacket2 {
    pub fn new() -> KKPacket2 {
        KKPacket2::from([0u8; KK_PACKET2BYTES])
    }
}

impl Default for KKPacket2 {
    fn default() -> Self {
        Self::new()
    }
}

impl NKPacket1 {
    pub fn new() -> NKPacket1 {
        NKPacket1::from([0u8; NK_PACKET1BYTES])
    }
}

impl Default for NKPacket1 {
    fn default() -> Self {
        Self::new()
    }
}

impl NKPacket2 {
    pub fn new() -> NKPacket2 {
        NKPacket2::from([0u8; NK_PACKET2BYTES])
    }
}

impl Default for NKPacket2 {
    fn default() -> Self {
        Self::new()
    }
}

impl XXPacket1 {
    pub fn new() -> XXPacket1 {
        XXPacket1::from([0u8; XX_PACKET1BYTES])
    }
}

impl Default for XXPacket1 {
    fn default() -> Self {
        Self::new()
    }
}

impl XXPacket2 {
    pub fn new() -> XXPacket2 {
        XXPacket2::from([0u8; XX_PACKET2BYTES])
    }
}

impl Default for XXPacket2 {
    fn default() -> Self {
        Self::new()
    }
}

impl XXPacket3 {
    pub fn new() -> XXPacket3 {
        XXPacket3::from([0u8; XX_PACKET3BYTES])
    }
}

impl Default for XXPacket3 {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyPair {
    pub fn gen() -> KeyPair {
        ensure_initialized();
        unsafe {
            let mut keypair_c = MaybeUninit::<ffi::hydro_kx_keypair>::uninit();
            ffi::hydro_kx_keygen(keypair_c.as_mut_ptr());
            KeyPair::from(keypair_c)
        }
    }

    pub fn gen_deterministic(seed: &Seed) -> KeyPair {
        ensure_initialized();
        unsafe {
            let mut keypair_c = MaybeUninit::<ffi::hydro_kx_keypair>::uninit();
            ffi::hydro_kx_keygen_deterministic(keypair_c.as_mut_ptr(), seed.0.as_ptr());
            KeyPair::from(keypair_c)
        }
    }
}

#[rustfmt::skip::macros(assert)]
#[cfg(test)]
mod tests {
    use core::convert::TryFrom;

    use crate::*;

    #[test]
    fn test_kx_deterministic_keygen() {
        init().unwrap();

        let seed = kx::Seed::gen();

        let a = kx::KeyPair::gen_deterministic(&seed);
        let b = kx::KeyPair::gen_deterministic(&seed);

        assert!(utils::equal(a.public_key, b.public_key));
        assert!(utils::equal(a.secret_key, b.secret_key));
    }

    #[test]
    fn test_kx_n() {
        init().unwrap();

        let server_static_keypair = kx::KeyPair::gen();
        let psk = kx::Psk::try_from("deadbeefdeadbeefdeadbeefdeadbeef").unwrap();
        let mut npacket1 = kx::NPacket1::new();

        let client_session_keypair =
            kx::n_1(&mut npacket1, Some(&psk), &server_static_keypair.public_key).unwrap();

        let server_session_keypair =
            kx::n_2(&npacket1, Some(&psk), &server_static_keypair).unwrap();

        assert!(utils::equal(client_session_keypair.tx, server_session_keypair.rx));
        assert!(utils::equal(client_session_keypair.rx, server_session_keypair.tx));
    }

    #[test]
    fn test_kx_n_without_psk() {
        init().unwrap();

        let server_static_keypair = kx::KeyPair::gen();
        let mut npacket1 = kx::NPacket1::new();

        let client_session_keypair =
            kx::n_1(&mut npacket1, None, &server_static_keypair.public_key).unwrap();

        let server_session_keypair = kx::n_2(&npacket1, None, &server_static_keypair).unwrap();

        assert!(utils::equal(client_session_keypair.tx, server_session_keypair.rx));
        assert!(utils::equal(client_session_keypair.rx, server_session_keypair.tx));
    }

    #[test]
    fn test_kx_n_fails_with_bogus_psk() {
        init().unwrap();

        let server_static_keypair = kx::KeyPair::gen();
        let psk = kx::Psk::try_from("deadbeefdeadbeefdeadbeefdeadbeef").unwrap();
        let bogus_psk = kx::Psk::try_from("ffffffffffffffffffffffffffffffff").unwrap();
        let mut npacket1 = kx::NPacket1::new();

        let _client_session_keypair =
            kx::n_1(&mut npacket1, Some(&psk), &server_static_keypair.public_key).unwrap();

        let result = kx::n_2(&npacket1, Some(&bogus_psk), &server_static_keypair);

        assert!(result.is_err());
    }

    #[test]
    fn test_kx_n_fails_with_bogus_pk() {
        init().unwrap();

        let server_static_keypair = kx::KeyPair::gen();
        let bogus_keypair = kx::KeyPair::gen();
        let psk = kx::Psk::try_from("deadbeefdeadbeefdeadbeefdeadbeef").unwrap();
        let mut npacket1 = kx::NPacket1::new();

        let _client_session_keypair =
            kx::n_1(&mut npacket1, Some(&psk), &bogus_keypair.public_key).unwrap();

        let result = kx::n_2(&npacket1, Some(&psk), &server_static_keypair);

        assert!(result.is_err());
    }

    #[test]
    fn test_kx_kk() {
        init().unwrap();

        let server_static_keypair = kx::KeyPair::gen();
        let client_static_keypair = kx::KeyPair::gen();
        let mut kkpacket1 = kx::KKPacket1::new();
        let mut kkpacket2 = kx::KKPacket2::new();
        let mut client_state = kx::State::new();

        kx::kk_1(
            &mut client_state,
            &mut kkpacket1,
            &server_static_keypair.public_key,
            &client_static_keypair,
        )
        .unwrap();

        let server_session_keypair = kx::kk_2(
            &mut kkpacket2,
            &kkpacket1,
            &client_static_keypair.public_key,
            &server_static_keypair,
        )
        .unwrap();

        let client_session_keypair =
            kx::kk_3(&mut client_state, &kkpacket2, &client_static_keypair).unwrap();

        assert!(utils::equal(client_session_keypair.tx, server_session_keypair.rx));
        assert!(utils::equal(client_session_keypair.rx, server_session_keypair.tx));
    }

    #[test]
    fn test_kx_kk_fails_with_bogus_pk() {
        init().unwrap();

        let server_static_keypair = kx::KeyPair::gen();
        let client_static_keypair = kx::KeyPair::gen();
        let bogus_keypair = kx::KeyPair::gen();
        let mut kkpacket1 = kx::KKPacket1::new();
        let mut kkpacket2 = kx::KKPacket2::new();
        let mut client_state = kx::State::new();

        kx::kk_1(
            &mut client_state,
            &mut kkpacket1,
            &bogus_keypair.public_key,
            &client_static_keypair,
        )
        .unwrap();

        let result = kx::kk_2(
            &mut kkpacket2,
            &kkpacket1,
            &client_static_keypair.public_key,
            &server_static_keypair,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_kx_nk() {
        init().unwrap();

        let server_static_keypair = kx::KeyPair::gen();
        let psk = kx::Psk::try_from("deadbeefdeadbeefdeadbeefdeadbeef").unwrap();
        let mut nkpacket1 = kx::NKPacket1::new();
        let mut nkpacket2 = kx::NKPacket2::new();
        let mut client_state = kx::State::new();

        kx::nk_1(
            &mut client_state,
            &mut nkpacket1,
            Some(&psk),
            &server_static_keypair.public_key,
        )
        .unwrap();

        let server_session_keypair = kx::nk_2(
            &mut nkpacket2,
            &nkpacket1,
            Some(&psk),
            &server_static_keypair,
        )
        .unwrap();

        let client_session_keypair = kx::nk_3(&mut client_state, &nkpacket2).unwrap();

        assert!(utils::equal(client_session_keypair.tx, server_session_keypair.rx));
        assert!(utils::equal(client_session_keypair.rx, server_session_keypair.tx));
    }

    #[test]
    fn test_kx_nk_without_psk() {
        init().unwrap();

        let server_static_keypair = kx::KeyPair::gen();
        let mut nkpacket1 = kx::NKPacket1::new();
        let mut nkpacket2 = kx::NKPacket2::new();
        let mut client_state = kx::State::new();

        kx::nk_1(
            &mut client_state,
            &mut nkpacket1,
            None,
            &server_static_keypair.public_key,
        )
        .unwrap();

        let server_session_keypair =
            kx::nk_2(&mut nkpacket2, &nkpacket1, None, &server_static_keypair).unwrap();

        let client_session_keypair = kx::nk_3(&mut client_state, &nkpacket2).unwrap();

        assert!(utils::equal(client_session_keypair.tx, server_session_keypair.rx));
        assert!(utils::equal(client_session_keypair.rx, server_session_keypair.tx));
    }

    #[test]
    fn test_kx_nk_fails_with_bogus_psk() {
        init().unwrap();

        let server_static_keypair = kx::KeyPair::gen();
        let psk = kx::Psk::try_from("deadbeefdeadbeefdeadbeefdeadbeef").unwrap();
        let bogus_psk = kx::Psk::try_from("ffffffffffffffffffffffffffffffff").unwrap();
        let mut nkpacket1 = kx::NKPacket1::new();
        let mut nkpacket2 = kx::NKPacket2::new();
        let mut client_state = kx::State::new();

        kx::nk_1(
            &mut client_state,
            &mut nkpacket1,
            Some(&bogus_psk),
            &server_static_keypair.public_key,
        )
        .unwrap();

        let _server_session_keypair = kx::nk_2(
            &mut nkpacket2,
            &nkpacket1,
            Some(&psk),
            &server_static_keypair,
        );

        let result = kx::nk_3(&mut client_state, &nkpacket2);

        assert!(result.is_err());
    }

    #[test]
    fn test_kx_nk_fails_with_bogus_pk() {
        init().unwrap();

        let server_static_keypair = kx::KeyPair::gen();
        let psk = kx::Psk::try_from("deadbeefdeadbeefdeadbeefdeadbeef").unwrap();
        let bogus_keypair = kx::KeyPair::gen();
        let mut nkpacket1 = kx::NKPacket1::new();
        let mut nkpacket2 = kx::NKPacket2::new();
        let mut client_state = kx::State::new();

        kx::nk_1(
            &mut client_state,
            &mut nkpacket1,
            Some(&psk),
            &bogus_keypair.public_key,
        )
        .unwrap();

        let result = kx::nk_2(
            &mut nkpacket2,
            &nkpacket1,
            Some(&psk),
            &server_static_keypair,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_kx_xx() {
        init().unwrap();

        let server_static_keypair = kx::KeyPair::gen();
        let client_static_keypair = kx::KeyPair::gen();
        let psk = kx::Psk::try_from("deadbeefdeadbeefdeadbeefdeadbeef").unwrap();
        let mut client_peer_public_key = kx::PublicKey::from([0u8; kx::PUBLICKEYBYTES]);
        let mut server_peer_public_key = kx::PublicKey::from([0u8; kx::PUBLICKEYBYTES]);
        let mut xxpacket1 = kx::XXPacket1::new();
        let mut xxpacket2 = kx::XXPacket2::new();
        let mut xxpacket3 = kx::XXPacket3::new();
        let mut client_state = kx::State::new();
        let mut server_state = kx::State::new();

        kx::xx_1(&mut client_state, &mut xxpacket1, Some(&psk)).unwrap();

        kx::xx_2(
            &mut server_state,
            &mut xxpacket2,
            &xxpacket1,
            Some(&psk),
            &server_static_keypair,
        )
        .unwrap();

        let client_session_keypair = kx::xx_3(
            &mut client_state,
            &mut xxpacket3,
            Some(&mut client_peer_public_key),
            &xxpacket2,
            Some(&psk),
            &client_static_keypair,
        )
        .unwrap();

        let server_session_keypair = kx::xx_4(
            &mut server_state,
            Some(&mut server_peer_public_key),
            &xxpacket3,
            Some(&psk),
        )
        .unwrap();

        assert!(utils::equal(client_session_keypair.tx, server_session_keypair.rx));
        assert!(utils::equal(client_session_keypair.rx, server_session_keypair.tx));
        assert!(utils::equal(client_peer_public_key, server_static_keypair.public_key));
        assert!(utils::equal(server_peer_public_key, client_static_keypair.public_key));
    }

    #[test]
    fn test_kx_xx_without_peer_pk() {
        init().unwrap();

        let server_static_keypair = kx::KeyPair::gen();
        let client_static_keypair = kx::KeyPair::gen();
        let psk = kx::Psk::try_from("deadbeefdeadbeefdeadbeefdeadbeef").unwrap();
        let mut xxpacket1 = kx::XXPacket1::new();
        let mut xxpacket2 = kx::XXPacket2::new();
        let mut xxpacket3 = kx::XXPacket3::new();
        let mut client_state = kx::State::new();
        let mut server_state = kx::State::new();

        kx::xx_1(&mut client_state, &mut xxpacket1, Some(&psk)).unwrap();

        kx::xx_2(
            &mut server_state,
            &mut xxpacket2,
            &xxpacket1,
            Some(&psk),
            &server_static_keypair,
        )
        .unwrap();

        let client_session_keypair = kx::xx_3(
            &mut client_state,
            &mut xxpacket3,
            None,
            &xxpacket2,
            Some(&psk),
            &client_static_keypair,
        )
        .unwrap();

        let server_session_keypair =
            kx::xx_4(&mut server_state, None, &xxpacket3, Some(&psk)).unwrap();

        assert!(utils::equal(client_session_keypair.tx, server_session_keypair.rx));
        assert!(utils::equal(client_session_keypair.rx, server_session_keypair.tx));
    }

    #[test]
    fn test_kx_xx_fails_with_bogus_psk() {
        init().unwrap();

        let server_static_keypair = kx::KeyPair::gen();
        let client_static_keypair = kx::KeyPair::gen();
        let psk = kx::Psk::try_from("deadbeefdeadbeefdeadbeefdeadbeef").unwrap();
        let bogus_psk = kx::Psk::try_from("ffffffffffffffffffffffffffffffff").unwrap();
        let mut xxpacket1 = kx::XXPacket1::new();
        let mut xxpacket2 = kx::XXPacket2::new();
        let mut client_state = kx::State::new();
        let mut server_state = kx::State::new();

        kx::xx_1(&mut client_state, &mut xxpacket1, Some(&psk)).unwrap();

        let result = kx::xx_2(
            &mut server_state,
            &mut xxpacket2,
            &xxpacket1,
            Some(&bogus_psk),
            &server_static_keypair,
        );

        assert!(result.is_err());

        let mut client_peer_public_key = kx::PublicKey::from([0u8; kx::PUBLICKEYBYTES]);
        let mut server_peer_public_key = kx::PublicKey::from([0u8; kx::PUBLICKEYBYTES]);
        let mut xxpacket1 = kx::XXPacket1::new();
        let mut xxpacket2 = kx::XXPacket2::new();
        let mut xxpacket3 = kx::XXPacket3::new();
        let mut client_state = kx::State::new();
        let mut server_state = kx::State::new();

        kx::xx_1(&mut client_state, &mut xxpacket1, Some(&psk)).unwrap();

        kx::xx_2(
            &mut server_state,
            &mut xxpacket2,
            &xxpacket1,
            Some(&psk),
            &server_static_keypair,
        )
        .unwrap();

        let _client_session_keypair = kx::xx_3(
            &mut client_state,
            &mut xxpacket3,
            Some(&mut client_peer_public_key),
            &xxpacket2,
            Some(&psk),
            &client_static_keypair,
        )
        .unwrap();

        let result = kx::xx_4(
            &mut server_state,
            Some(&mut server_peer_public_key),
            &xxpacket3,
            Some(&bogus_psk),
        );

        assert!(result.is_err());
    }
}
