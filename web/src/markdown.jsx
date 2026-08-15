// rich turns the GitHub changelog's **bold** and [label](url) into nodes.
export function rich(text) {
  const out = []
  const re = /(\*\*[^*]+\*\*|\[[^\]]+\]\(https?:\/\/[^)\s]+\))/g
  let last = 0
  let m
  let k = 0
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index))
    const tok = m[0]
    if (tok.startsWith('**')) {
      out.push(<strong key={k++}>{tok.slice(2, -2)}</strong>)
    } else {
      const mm = tok.match(/^\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)$/)
      out.push(
        <a key={k++} href={mm[2]} target="_blank" rel="noreferrer">
          {mm[1]}
        </a>,
      )
    }
    last = m.index + tok.length
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

// renderMarkdown renders a release body with ## / ### headers and bullets.
export function renderMarkdown(body, emptyNote = 'No changelog was published for this release.') {
  if (!body || !body.trim()) {
    return <p className="modal-note">{emptyNote}</p>
  }
  const out = []
  let list = []
  let key = 0
  const flush = () => {
    if (list.length) {
      out.push(<ul key={`ul-${key++}`}>{list}</ul>)
      list = []
    }
  }
  body.split('\n').forEach((line) => {
    const t = line.trim()
    if (/^###\s+/.test(t)) {
      flush()
      out.push(<h5 key={key++}>{t.replace(/^###\s+/, '')}</h5>)
    } else if (/^##\s+/.test(t)) {
      flush()
      out.push(<h4 key={key++}>{t.replace(/^##\s+/, '')}</h4>)
    } else if (/^[-*]\s+/.test(t)) {
      list.push(<li key={key++}>{rich(t.replace(/^[-*]\s+/, ''))}</li>)
    } else if (t === '') {
      flush()
    } else {
      flush()
      out.push(<p key={key++}>{rich(t)}</p>)
    }
  })
  flush()
  return out
}
