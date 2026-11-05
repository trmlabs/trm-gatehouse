// Pure Slack text-formatting helpers. Kept free of side effects so they can be
// unit-tested without standing up the Bolt app.

// Slack rejects messages over 40,000 chars (msg_too_long); chunk well under that on line boundaries.
export const SLACK_MAX_CHARS = 3900;

/** Split text into chunks of at most `max`, on line boundaries; an over-long line is hard-split. */
export function chunkText(text: string, max = SLACK_MAX_CHARS): string[] {
  const chunks: string[] = [];
  let current = "";

  for (const line of text.split("\n")) {
    if (line.length > max) {
      if (current) {
        chunks.push(current);
        current = "";
      }
      for (let i = 0; i < line.length; i += max) chunks.push(line.slice(i, i + max));
      continue;
    }

    if (current && current.length + line.length + 1 > max) {
      chunks.push(current);
      current = line;
    } else {
      current = current ? `${current}\n${line}` : line;
    }
  }

  if (current) chunks.push(current);
  return chunks.length > 0 ? chunks : [""];
}
