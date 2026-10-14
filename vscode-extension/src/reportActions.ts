const handled = new Set(['ready', 'pick', 'raw', 'folder', 'provision', 'output', 'finding']);

export function reportButtonCommand(action: string): string | undefined {
    switch (action) {
        case 'pick': return 'compliance.openReportFile';
        case 'raw': return 'compliance.openRawReport';
        case 'folder': return 'compliance.openSessionFolder';
        case 'provision': return 'compliance.provisionTools';
        default: return undefined;
    }
}

export function unwiredReportActions(markup: string): string[] {
    const actions = new Set<string>();
    for (const match of markup.matchAll(/data-action="([^"]+)"/g)) { actions.add(match[1]); }
    return [...actions].filter(action => !handled.has(action) || (reportButtonCommand(action) === undefined && !['output', 'finding', 'ready'].includes(action)));
}
