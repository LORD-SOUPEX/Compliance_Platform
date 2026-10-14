let expectedEngine = '';

export function setExpectedEngineVersion(version: string): void {
    expectedEngine = version;
}

export function expectedEngineVersion(): string {
    return expectedEngine;
}

export function engineVersionMismatch(running: string | undefined, expected: string): boolean {
    return expected !== '' && running !== expected;
}
