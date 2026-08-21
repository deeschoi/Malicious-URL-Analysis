import {
  parseAnalystBody,
  parseAnalystReply,
  splitInlineEmphasis,
  type AnalystBlock,
} from "../analystReply";

function InlineText({ text }: { text: string }) {
  return (
    <>
      {splitInlineEmphasis(text).map((part, index) =>
        part.bold ? (
          <strong key={index}>{part.text}</strong>
        ) : (
          <span key={index}>{part.text}</span>
        ),
      )}
    </>
  );
}

function AnalystBlocks({ blocks }: { blocks: AnalystBlock[] }) {
  const nodes: JSX.Element[] = [];
  let bulletGroup: AnalystBlock[] = [];

  function flushBullets() {
    if (bulletGroup.length === 0) return;
    nodes.push(
      <ul key={`bullets-${nodes.length}`} className="analyst-list">
        {bulletGroup.map((block, index) => (
          <li key={index}>
            <InlineText text={block.text} />
          </li>
        ))}
      </ul>,
    );
    bulletGroup = [];
  }

  for (const block of blocks) {
    if (block.kind === "bullet") {
      bulletGroup.push(block);
      continue;
    }
    flushBullets();
    if (block.kind === "subhead") {
      nodes.push(
        <h5 key={`subhead-${nodes.length}`} className="analyst-subhead">
          {block.text}
        </h5>,
      );
    } else {
      nodes.push(
        <p key={`para-${nodes.length}`} className="analyst-paragraph">
          <InlineText text={block.text} />
        </p>,
      );
    }
  }
  flushBullets();

  return <div className="analyst-body">{nodes}</div>;
}

export function AnalystReply({ content }: { content: string }) {
  const sections = parseAnalystReply(content);
  if (sections) {
    return (
      <div className="analyst-reply">
        <section className="analyst-panel is-findings" aria-label="Findings">
          <h4 className="analyst-panel-title">Findings</h4>
          <AnalystBlocks blocks={sections.findings} />
        </section>
        {sections.commentary.length > 0 ? (
          <section className="analyst-panel is-commentary" aria-label="Commentary">
            <h4 className="analyst-panel-title">Commentary</h4>
            <AnalystBlocks blocks={sections.commentary} />
          </section>
        ) : null}
      </div>
    );
  }

  return <AnalystBlocks blocks={parseAnalystBody(content)} />;
}
