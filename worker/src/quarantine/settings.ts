import { QUARANTINE, type QuarantineSettings } from "@krynodes/protocol";

interface SettingsRow {
  cutoff: number | null;
  scan: number;
  agree: number;
  stop: number;
}

export async function readSettings(
  db: D1Database,
  owner: string,
): Promise<QuarantineSettings> {
  const row = await db
    .prepare(
      "SELECT cutoff, scan, agree, stop FROM quarantine_settings WHERE owner_user_id = ?",
    )
    .bind(owner)
    .first<SettingsRow>();
  return row
    ? ({
        cutoff: row.cutoff,
        scan: row.scan,
        agree: row.agree,
        stop: row.stop === 1,
      } as QuarantineSettings)
    : { ...QUARANTINE.defaults };
}

export const settingsText = (settings: QuarantineSettings) =>
  `cutoff:${settings.cutoff ?? "none"} scan:${settings.scan} agree:${settings.agree} stop:${settings.stop}`;

export const writeSettings = (
  db: D1Database,
  owner: string,
  settings: QuarantineSettings,
  at: string,
) =>
  db
    .prepare(
      `INSERT INTO quarantine_settings (owner_user_id, cutoff, scan, agree, stop, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (owner_user_id) DO UPDATE SET cutoff = excluded.cutoff,
         scan = excluded.scan, agree = excluded.agree, stop = excluded.stop,
         updated_at = excluded.updated_at`,
    )
    .bind(
      owner,
      settings.cutoff,
      settings.scan,
      settings.agree,
      settings.stop ? 1 : 0,
      at,
    );
