// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { passworder } from 'browser-passworder';

export function encrypt(password: string, plaintext: string): string {
    return passworder.encrypt(password, plaintext)
}

export function decrypt(password: string, ciphertext: string): string {
    return passworder.decrypt(password, ciphertext)
}