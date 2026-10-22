export interface ProvisionTool {
    command: string;
    version: string;
    source: string;
}

export const machineConsentKey = 'compliance.machineConsent';

export interface MachineConsent {
    schema_version: 1;
    decision: 'accepted' | 'refused';
}

export function hasMachineConsent(memory: MachineConsent | undefined): boolean {
    return memory?.schema_version === 1 && memory.decision === 'accepted';
}

export function shouldAskMachineConsent(memory: MachineConsent | undefined): boolean {
    return !memory || memory.schema_version !== 1 || (memory.decision !== 'accepted' && memory.decision !== 'refused');
}

export function machineConsentText(): string {
    return 'Autorisation unique pour cette machine.\n\nCompliance téléchargera et installera les outils du registre, puis les exécutera, réseau compris, pour auditer les dépôts que vous choisissez. Ce choix est mémorisé et ne sera plus redemandé, y compris pour un autre dépôt.\n\nLes archives sont extraites dans le dossier utilisateur, sans droits administrateur. Cette autorisation ne constitue pas un bac à sable.';
}

export function classifyProvisionError(message: string): { code: string; message: string } {
    const lower = message.toLowerCase();
    if (lower.includes('absent du manifeste') || lower.includes('outil absent du manifeste')) {
        return { code: 'manifest', message: `${message} Aucun contournement pip ou Homebrew n'est proposé.` };
    }
    if (lower.includes('échec') || lower.includes('echec')) {
        return { code: 'partial', message };
    }
    if (lower.includes('proxy') || lower.includes('407')) {
        return { code: 'proxy', message };
    }
    if (lower.includes('x509') || lower.includes('certificate') || lower.includes('certificat') || lower.includes('tls')) {
        return { code: 'certificate', message };
    }
    if (!lower.includes('code http') && (lower.includes('no such host') || lower.includes('connection refused') || lower.includes('i/o timeout') || lower.includes('dial tcp'))) {
        return { code: 'network', message: 'Réseau indisponible. Relancez l’installation quand la connexion est disponible.' };
    }
    return { code: 'other', message };
}

export function selectManifestTools(manifest: unknown, platform: string, commands: string[]): ProvisionTool[] {
    if (!manifest || typeof manifest !== 'object') { return []; }
    const platforms = (manifest as { platforms?: Record<string, { tools?: Record<string, { version?: string; archive_url?: string }> }> }).platforms;
    // Windows 11 on ARM runs x64 tools through emulation: same rule as the engine (PlatformCandidates).
    const candidates = platform === 'windows-arm64' ? ['windows-arm64', 'windows-x64'] : [platform];
    const tools: Record<string, { version?: string; archive_url?: string }> = {};
    for (const candidate of [...candidates].reverse()) { Object.assign(tools, platforms?.[candidate]?.tools || {}); }
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
