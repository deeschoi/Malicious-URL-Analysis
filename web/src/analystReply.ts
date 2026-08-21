/** Parse analyst replies into Findings vs Commentary, with markdown-lite blocks. */

export type AnalystBlock =
  | { kind: "subhead"; text: string }
  | { kind: "bullet"; text: string }
  | { kind: "paragraph"; text: string };

export interface AnalystSections {
  findings: AnalystBlock[];
  commentary: AnalystBlock[];
}

const SECTION_HEADING = /^##\s*(findings|commentary)\s*$/i;
const LEGACY_HEADING = /^(?:\*\*)?(findings|commentary)(?:\*\*)?\s*:?\s*$/i;
const BULLET_LINE = /^(\s*)[-*•]\s+(.+)$/;

function isSectionHeading(line: string): boolean {
  const trimmed = line.trim();
  return SECTION_HEADING.test(trimmed) || LEGACY_HEADING.test(trimmed);
}

function sectionLabel(line: string): "findings" | "commentary" | null {
  const trimmed = line.trim();
  if (!isSectionHeading(trimmed)) return null;
  const label = trimmed.replace(/^##\s*|\*\*/g, "").replace(/:$/, "").trim().toLowerCase();
  if (label.startsWith("finding")) return "findings";
  if (label.startsWith("commentary")) return "commentary";
  return null;
}

function splitOnSections(content: string): { findings: string; commentary: string } | null {
  const lines = content.trim().split("\n");
  let findingsStart = -1;
  let commentaryStart = -1;

  for (let index = 0; index < lines.length; index += 1) {
    const label = sectionLabel(lines[index]);
    if (label === "findings" && findingsStart === -1) {
      findingsStart = index + 1;
    } else if (label === "commentary" && commentaryStart === -1) {
      commentaryStart = index + 1;
    }
  }

  if (findingsStart === -1) {
    return null;
  }

  if (commentaryStart === -1) {
    return {
      findings: lines.slice(findingsStart).join("\n").trim(),
      commentary: "",
    };
  }

  if (commentaryStart <= findingsStart) {
    return null;
  }

  return {
    findings: lines.slice(findingsStart, commentaryStart - 1).join("\n").trim(),
    commentary: lines.slice(commentaryStart).join("\n").trim(),
  };
}

/** Infer sections when the model used bold feature-group headers but skipped ## headings. */
function inferSections(content: string): { findings: string; commentary: string } | null {
  const text = content.trim();
  const marker = text.search(
    /\*\*(?:key features|features that|toward phishing|toward legitimate|signals toward)/i,
  );
  if (marker < 0) {
    return null;
  }

  const intro = text.slice(0, marker).trim();
  const rest = text.slice(marker).trim();
  const blocks = rest.split(/\n\s*\n/);
  const commentaryBlocks: string[] = intro ? [intro] : [];
  const findingBlocks: string[] = [];

  for (const block of blocks) {
    const trimmed = block.trim();
    if (!trimmed) continue;
    const hasEvidence =
      /^\*\*(?:key features|features that|toward phishing|toward legitimate)/im.test(trimmed) ||
      /^[-*•]\s+/m.test(trimmed);
    if (hasEvidence) {
      findingBlocks.push(trimmed);
    } else {
      commentaryBlocks.push(trimmed);
    }
  }

  if (findingBlocks.length === 0) {
    return null;
  }

  return {
    findings: findingBlocks.join("\n\n").trim(),
    commentary: commentaryBlocks.join("\n\n").trim(),
  };
}

function parseBlocks(text: string): AnalystBlock[] {
  const blocks: AnalystBlock[] = [];
  const lines = text.split("\n");
  let paragraph: string[] = [];
  let bullets: string[] = [];

  function flushParagraph() {
    if (paragraph.length === 0) return;
    blocks.push({ kind: "paragraph", text: paragraph.join(" ").trim() });
    paragraph = [];
  }

  function flushBullets() {
    if (bullets.length === 0) return;
    for (const bullet of bullets) {
      blocks.push({ kind: "bullet", text: bullet });
    }
    bullets = [];
  }

  for (const raw of lines) {
    const trimmed = raw.trim();
    if (!trimmed) {
      flushParagraph();
      flushBullets();
      continue;
    }

    if (isSectionHeading(trimmed)) {
      flushParagraph();
      flushBullets();
      continue;
    }

    const subhead = trimmed.match(/^\*\*(.+)\*\*$/);
    if (subhead) {
      flushParagraph();
      flushBullets();
      blocks.push({ kind: "subhead", text: subhead[1].trim() });
      continue;
    }

    const bulletMatch = raw.match(BULLET_LINE);
    if (bulletMatch) {
      flushParagraph();
      const bulletText = bulletMatch[2].trim();
      const bulletSubhead = bulletText.match(/^\*\*(.+)\*\*$/);
      if (bulletSubhead) {
        flushBullets();
        blocks.push({ kind: "subhead", text: bulletSubhead[1].trim() });
        continue;
      }
      bullets.push(bulletText);
      continue;
    }

    flushBullets();
    paragraph.push(trimmed);
  }

  flushParagraph();
  flushBullets();
  return blocks;
}

function splitLooseSections(content: string): { findings: string; commentary: string } | null {
  const lines = content.trim().split("\n");
  const prose: string[] = [];
  const evidence: string[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || isSectionHeading(trimmed)) continue;
    if (BULLET_LINE.test(line) || /^\*\*(?:key features|features that|toward phishing|toward legitimate)/i.test(trimmed)) {
      evidence.push(line);
    } else {
      prose.push(trimmed);
    }
  }

  if (evidence.length === 0) {
    return null;
  }

  return {
    findings: evidence.join("\n").trim(),
    commentary: prose.join("\n\n").trim(),
  };
}

export function parseAnalystReply(content: string): AnalystSections | null {
  const sections = splitOnSections(content) ?? inferSections(content) ?? splitLooseSections(content);
  if (!sections) {
    return null;
  }

  const findings = parseBlocks(sections.findings);
  const commentary = sections.commentary ? parseBlocks(sections.commentary) : [];
  if (findings.length === 0) {
    return null;
  }

  return { findings, commentary };
}

/** Render markdown-lite inline emphasis: **bold** segments. */
export function splitInlineEmphasis(text: string): Array<{ bold: boolean; text: string }> {
  const parts: Array<{ bold: boolean; text: string }> = [];
  const pattern = /\*\*(.+?)\*\*/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push({ bold: false, text: text.slice(lastIndex, match.index) });
    }
    parts.push({ bold: true, text: match[1] });
    lastIndex = pattern.lastIndex;
  }

  if (lastIndex < text.length) {
    parts.push({ bold: false, text: text.slice(lastIndex) });
  }

  if (parts.length === 0) {
    parts.push({ bold: false, text });
  }

  return parts;
}

export function parseAnalystBody(content: string): AnalystBlock[] {
  const structured = parseAnalystReply(content);
  if (structured) {
    return [...structured.findings, ...structured.commentary];
  }
  return parseBlocks(content.trim());
}
