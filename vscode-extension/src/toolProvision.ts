export interface ProvisionTool {
    command: string;
    version: string;
    source: string;
}

export interface ConsentMemory {
    fingerprint: string;
    decision: 'accepted' | 'refused';
    installed: boolean;
}

export function fingerprint(commands: string[]): string {
    return [...commands].sort().join('\n');
}

export function shouldPrompt(memory: ConsentMemory | undefined, id: string, trigger: 'auto' | 'manual'): boolean {
    if (!memory || memory.fingerprint !== id) { return true; }
    if (memory.decision === 'refused' || memory.installed) { return trigger === 'manual'; }
    return true;
}

export function consentText(tools: ProvisionTool[]): string {
    const lines = tools.map(tool => `- ${tool.command} ${tool.version}\n  source : ${tool.source}\n  taille : non déclarée dans le manifeste`);
    return `Installation depuis le manifeste. Cet accord autorise le téléchargement HTTPS, une seule fois pour cette liste.\n\n${lines.join('\n')}\n\nChaque archive est extraite dans le dossier utilisateur, sans droits administrateur.`;
}

export function classifyProvisionError(message: string): { code: string; message: string } {
    const lower = message.toLowerCase();
    if (lower.includes('absent du manifeste') || lower.includes('outil absent du manifeste')) {
        return { code: 'manifest', message: `${message} Aucun contournement pip ou Homebrew n'est proposé.` };
    }
    if (lower.includes('échec') || lower.includes('echec')) {
        return { code: 'partial', message };
    }
    if (lower.includes('proxy')) {
        return { code: 'proxy', message };
    }
    if (!lower.includes('code http') && (lower.includes('no such host') || lower.includes('connection refused') || lower.includes('i/o timeout') || lower.includes('dial tcp'))) {
        return { code: 'network', message: 'Réseau indisponible. Relancez l’installation quand la connexion est disponible.' };
    }
    return { code: 'other', message };
}

export function selectManifestTools(manifest: unknown, platform: string, commands: string[]): ProvisionTool[] {
    if (!manifest || typeof manifest !== 'object') { return []; }
    const platforms = (manifest as { platforms?: Record<string, { tools?: Record<string, { version?: string; archive_url?: string }> }> }).platforms;
    const tools = platforms?.[platform]?.tools;
    if (!tools) { return []; }
    return commands.filter(command => tools[command]).map(command => ({
        command,
        version: String(tools[command].version || ''),
        source: String(tools[command].archive_url || '')
    }));
}

export function missingToolCommands(report: unknown): string[] {
    if (!report || typeof report !== 'object') { return []; }
    const value = report as { execution_plan?: { controls?: unknown[] }; execution_results?: unknown[] };
    const commands = new Map<string, string>();
    for (const control of value.execution_plan?.controls || []) {
        if (!control || typeof control !== 'object') { continue; }
        const item = control as { id?: string; tool?: { command?: string } };
        if (typeof item.id === 'string' && item.tool && typeof item.tool.command === 'string' && item.tool.command && item.tool.command !== 'none') {
            commands.set(item.id, item.tool.command);
        }
    }
    const missing = new Set<string>();
    for (const result of value.execution_results || []) {
        if (!result || typeof result !== 'object') { continue; }
        const item = result as { control_id?: string; diagnostics?: { code?: string }[] };
        const code = item.diagnostics?.[0]?.code;
        if (code === 'tool_unavailable' && typeof item.control_id === 'string' && commands.get(item.control_id)) {
            missing.add(commands.get(item.control_id)!);
        }
    }
    return [...missing];
}
