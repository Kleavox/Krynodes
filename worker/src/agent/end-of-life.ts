import { z } from "zod";

export type EndOfLife = Record<string, Record<string, string>>;

const PRODUCTS = {
  debian: "debian",
  ubuntu: "ubuntu",
  rhel: "rhel",
  rocky: "rocky-linux",
  almalinux: "almalinux",
  ol: "oracle-linux",
  centos: "centos-stream",
} as const;

const DATE = /^\d{4}-\d{2}-\d{2}$/u;
const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];
const WARN_MS = 90 * 86_400_000;

const answerSchema = z.object({
  result: z.object({
    releases: z.array(
      z.object({ name: z.string(), eolFrom: z.string().nullable() }),
    ),
  }),
});

async function releasesOf(
  product: string,
): Promise<Record<string, string> | null> {
  try {
    const response = await fetch(
      `https://endoflife.date/api/v1/products/${product}`,
      { headers: { "user-agent": "kry-worker" } },
    );
    if (response.status !== 200) return null;
    const answer = answerSchema.safeParse(await response.json());
    if (!answer.success) return null;
    const dates = Object.fromEntries(
      answer.data.result.releases.flatMap((release) =>
        release.eolFrom !== null && DATE.test(release.eolFrom)
          ? [[release.name, release.eolFrom]]
          : [],
      ),
    );
    return Object.keys(dates).length > 0 ? dates : null;
  } catch {
    return null;
  }
}

export async function readEndOfLife(db: D1Database): Promise<EndOfLife> {
  const row = await db
    .prepare("SELECT value FROM settings WHERE key = 'os_end_of_life'")
    .first<{ value: string | null }>();
  try {
    const table = JSON.parse(row?.value ?? "{}") as unknown;
    return table && typeof table === "object" && !Array.isArray(table)
      ? (table as EndOfLife)
      : {};
  } catch {
    return {};
  }
}

export async function runEndOfLifeCheck(db: D1Database): Promise<void> {
  const table = await readEndOfLife(db);
  const products = Object.values(PRODUCTS);
  const answers = await Promise.all(products.map(releasesOf));
  products.forEach((product, index) => {
    const dates = answers[index];
    if (dates) table[product] = dates;
  });
  await db
    .prepare(
      `INSERT INTO settings (key, value, updated_at) VALUES ('os_end_of_life', ?, ?)
       ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    )
    .bind(JSON.stringify(table), new Date().toISOString())
    .run();
}

export function endOfLifeDate(
  table: EndOfLife,
  id: string,
  version: string,
): string | null {
  if (!Object.hasOwn(PRODUCTS, id)) return null;
  const dates = table[PRODUCTS[id as keyof typeof PRODUCTS]];
  const release = id === "ubuntu" ? version : version.split(".")[0]!;
  const date = dates && Object.hasOwn(dates, release) ? dates[release] : null;
  return typeof date === "string" ? date : null;
}

const dayOf = (date: string) => {
  const [year, month, day] = date.split("-");
  return `${Number(day)} ${MONTHS[Number(month) - 1]} ${year}`;
};

export function eolFinding(
  name: string,
  date: string | null,
  now: number,
): { id: "os-eol"; severity: "serious" | "warning"; detail: string } | null {
  if (date === null || !DATE.test(date)) return null;
  const end = Date.parse(`${date}T00:00:00Z`);
  if (now > end) {
    return {
      id: "os-eol",
      severity: "serious",
      detail: `${name} no longer gets security updates (since ${dayOf(date)})`,
    };
  }
  if (end - now <= WARN_MS) {
    return {
      id: "os-eol",
      severity: "warning",
      detail: `${name} stops getting security updates on ${dayOf(date)}`,
    };
  }
  return null;
}
