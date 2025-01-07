// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.


export interface IKeyRotationPolicy {
    rotation_interval_seconds: number;
    grace_period_seconds: number;
}
