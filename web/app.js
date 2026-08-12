const $ = (sel) => document.querySelector(sel);
const GAUGE_CIRCUMFERENCE = 327;

/* ---------------- tabs ---------------- */

document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('is-active'));
    document.querySelectorAll('.view').forEach((v) => v.classList.remove('is-active'));
    tab.classList.add('is-active');
    $(`#view-${tab.dataset.view}`).classList.add('is-active');
    if (tab.dataset.view === 'findings') loadFindings();
  });
});

/* ---------------- scanning ---------------- */

document.querySelectorAll('.chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    $('#url-input').value = chip.dataset.url;
    $('#scan-form').requestSubmit();
  });
});

$('#scan-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const url = $('#url-input').value.trim();
  if (!url) return;

  setStatus('Fetching the page, inspecting its certificate and parsing its HTML…');
  $('#result').hidden = true;
  $('#scan-button').disabled = true;

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || 'Scan failed.');
    render(payload);
    clearStatus();
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    $('#scan-button').disabled = false;
  }
});

function setStatus(message, isError = false) {
  const el = $('#status');
  el.textContent = message;
  el.classList.toggle('is-error', isError);
  el.hidden = false;
}

function clearStatus() { $('#status').hidden = true; }

/* ---------------- rendering ---------------- */

const BADGE_CLASS = {
  phishing: 'is-phishing',
  suspicious: 'is-suspicious',
  'probably safe': 'is-safe',
  legitimate: 'is-safe',
};

const GAUGE_COLOUR = {
  phishing: '#ff5f56',
  suspicious: '#f5a524',
  'probably safe': '#35c98b',
  legitimate: '#35c98b',
};

function render(result) {
  $('#result').hidden = false;

  const badge = $('#verdict-badge');
  badge.textContent = result.verdict;
  badge.className = `badge ${BADGE_CLASS[result.verdict] || ''}`;

  $('#verdict-url').textContent = result.final_url;
  $('#verdict-rationale').textContent = result.rationale;

  const pct = result.probability * 100;
  $('#gauge-value').textContent = `${pct.toFixed(pct < 1 ? 2 : 0)}%`;
  const arc = $('#gauge-arc');
  arc.style.stroke = GAUGE_COLOUR[result.verdict] || '#35c98b';
  arc.style.strokeDashoffset = GAUGE_CIRCUMFERENCE * (1 - result.probability);

  const notes = $('#notes');
  notes.innerHTML = '';
  const messages = [...(result.notes || [])];
  if (result.error) messages.unshift(result.error);
  messages.forEach((text) => {
    const div = document.createElement('div');
    div.className = 'note';
    div.textContent = text;
    notes.appendChild(div);
  });

  renderSignals(result.signals);

  const c = result.coverage;
  fillList('#coverage', [
    ['Page downloaded', c.page_fetched ? 'yes' : 'no'],
    ['Certificate inspected', c.tls_checked ? 'yes' : 'no'],
    ['Signals used', `${c.features_used} of ${c.features_in_dataset}`],
    ['Unavailable in 2026', `${c.features_unavailable} features`],
    ['Model', result.model],
  ]);

  const q = result.model_quality;
  fillList('#quality', [
    ['Held-out accuracy', `${(q.accuracy * 100).toFixed(1)}%`],
    ['AUROC', q.auroc.toFixed(3)],
    ['Phishing caught at warn level', `${(q.recall_at_warn * 100).toFixed(0)}%`],
    ['False alarm rate', `${(q.false_positive_rate_at_warn * 100).toFixed(1)}%`],
    ['Warn / block thresholds',
      `${q.warn_threshold.toFixed(2)} / ${q.block_threshold.toFixed(2)}`],
  ]);
}

function renderSignals(signals) {
  const list = $('#signals');
  list.innerHTML = '';
  const scale = Math.max(...signals.map((s) => Math.abs(s.contribution)), 0.5);

  signals.forEach((signal) => {
    const item = document.createElement('li');
    item.className = 'signal' + (signal.measured ? '' : ' is-unmeasured');

    const name = document.createElement('div');
    name.innerHTML = `<span class="signal-name"></span><span class="signal-value"></span>`;
    name.querySelector('.signal-name').textContent = signal.label;
    name.querySelector('.signal-value').textContent =
      signal.measured ? signal.value_meaning : 'Could not be measured';
    if (signal.encoding_unreliable) {
      const flag = document.createElement('span');
      flag.className = 'signal-flag';
      flag.textContent = 'encoding unreliable';
      flag.title = 'In this dataset the feature behaves opposite to its documented meaning.';
      name.appendChild(flag);
    }

    const evidence = document.createElement('div');
    evidence.className = 'signal-evidence';
    evidence.textContent = signal.evidence;

    const width = (Math.abs(signal.contribution) / scale) * 50;
    const dir = signal.contribution >= 0 ? 'up' : 'down';

    const bar = document.createElement('div');
    bar.className = 'bar';
    bar.innerHTML = `
      <span class="bar-axis"></span>
      <span class="bar-fill ${dir}" style="width:${width}%"></span>`;

    const score = document.createElement('div');
    score.className = `signal-score ${Math.abs(signal.contribution) < 0.005 ? 'flat' : dir}`;
    score.textContent = `${signal.contribution >= 0 ? '+' : '\u2212'}${Math.abs(signal.contribution).toFixed(2)}`;
    score.title = signal.direction;

    item.append(name, evidence, bar, score);
    list.appendChild(item);
  });
}

function fillList(selector, pairs) {
  const dl = $(selector);
  dl.innerHTML = '';
  pairs.forEach(([term, value]) => {
    const dt = document.createElement('dt');
    dt.textContent = term;
    const dd = document.createElement('dd');
    dd.textContent = value;
    dl.append(dt, dd);
  });
}

/* ---------------- findings ---------------- */

let findingsLoaded = false;

async function loadFindings() {
  if (findingsLoaded) return;
  findingsLoaded = true;

  const container = $('#findings');
  try {
    const data = await (await fetch('/api/findings')).json();
    container.innerHTML = '';
    container.append(
      leakageCard(data),
      encodingCard(data),
      obsolescenceCard(data),
    );
  } catch (error) {
    container.innerHTML = `<p class="status is-error">Could not load findings: ${error.message}</p>`;
    findingsLoaded = false;
  }
}

function card(title, lede) {
  const el = document.createElement('section');
  el.className = 'finding';
  el.innerHTML = `<h3></h3><p class="lede"></p>`;
  el.querySelector('h3').textContent = title;
  el.querySelector('.lede').textContent = lede;
  return el;
}

function leakageCard(data) {
  const el = card(
    'Duplicate feature vectors inflate the published accuracy',
    'Roughly half the dataset consists of repeated feature patterns. Under a random split ' +
    'most test rows have already been seen during training, so the model is scored partly ' +
    'on memory. Re-partitioning so each pattern falls entirely on one side lowers every ' +
    "score, and the drop is largest for the models with the most capacity to memorise."
  );

  const l = data.leakage || {};
  const stats = document.createElement('div');
  stats.className = 'stat-row';
  stats.innerHTML = `
    <div class="stat"><strong>${pct(l.duplicate_row_fraction)}</strong><span>of rows are duplicate patterns</span></div>
    <div class="stat"><strong>${pct(l.random_split_test_rows_seen_in_train)}</strong><span>of test rows already seen in training</span></div>
    <div class="stat"><strong>${l.conflicting_label_patterns ?? '—'}</strong><span>patterns with contradictory labels</span></div>`;
  el.appendChild(stats);

  el.appendChild(table(
    ['Model', 'Random split', 'Grouped split', 'Optimism'],
    (data.models || []).map((m) => [
      m.model,
      { value: fixed(m.random_accuracy, 4), num: true },
      { value: fixed(m.grouped_accuracy, 4), num: true },
      { value: `+${fixed(m.accuracy_optimism, 4)}`, num: true,
        cls: m.accuracy_optimism > 0.015 ? 'bad' : '' },
    ])
  ));
  return el;
}

function encodingCard(data) {
  const reversed = data.reversed_features || [];
  const el = card(
    `${reversed.length} features are encoded backwards from their documented meaning`,
    'The source paper defines -1 as a phishing indicator, so the phishing rate should fall ' +
    'as the encoded value rises. For these features the data does the opposite. This is ' +
    'measured directly from the raw table, with no model involved, and it means the ' +
    'published feature definitions cannot be taken at face value.'
  );

  const audit = (data.encoding_audit || []).filter((row) => row.verdict === 'reversed');
  el.appendChild(table(
    ['Feature', 'Documented -1 means', 'P(phish | -1)', 'P(phish | +1)'],
    audit.map((row) => [
      row.feature,
      row['documented -1 means'],
      { value: fixed(row['P(phish|-1)'], 3), num: true },
      { value: fixed(row['P(phish|+1)'], 3), num: true, cls: 'bad' },
    ])
  ));

  if ((data.no_signal_features || []).length) {
    const p = document.createElement('p');
    p.className = 'lede';
    p.style.marginTop = '16px';
    p.textContent = 'A further set carries no marginal signal at all, with an identical ' +
      'phishing rate at every value:';
    const pills = document.createElement('ul');
    pills.className = 'pill-list';
    data.no_signal_features.forEach((f) => {
      const li = document.createElement('li');
      li.className = 'pill';
      li.textContent = f;
      pills.appendChild(li);
    });
    el.append(p, pills);
  }
  return el;
}

function obsolescenceCard(data) {
  const el = card(
    'What survives when 2012-era features disappear',
    'Five features depend on services that no longer exist. Dropping them costs about two ' +
    'accuracy points, so a model that can actually run today remains viable. Removing the ' +
    'certificate signal hurts far more, and the URL string on its own is not enough.'
  );

  el.appendChild(table(
    ['Feature set', 'Features', 'Accuracy', 'Change'],
    (data.scenarios || []).map((s) => [
      s.scenario,
      { value: s.n_features, num: true },
      { value: fixed(s.accuracy, 4), num: true },
      { value: s.delta_vs_full === 0 ? '—' : fixed(s.delta_vs_full, 4), num: true,
        cls: s.delta_vs_full < -0.02 ? 'bad' : s.delta_vs_full >= 0 ? 'good' : '' },
    ])
  ));

  const unavailable = data.unavailable_features || [];
  if (unavailable.length) {
    const p = document.createElement('p');
    p.className = 'lede';
    p.style.marginTop = '18px';
    p.textContent = 'Why each of those five can no longer be computed:';
    el.appendChild(p);
    el.appendChild(table(
      ['Feature', 'Reason'],
      unavailable.map((u) => [u.feature, u.reason])
    ));
  }
  return el;
}

function table(headers, rows) {
  const el = document.createElement('table');
  const thead = document.createElement('thead');
  const tr = document.createElement('tr');
  headers.forEach((h) => {
    const th = document.createElement('th');
    th.textContent = h;
    tr.appendChild(th);
  });
  thead.appendChild(tr);

  const tbody = document.createElement('tbody');
  rows.forEach((cells) => {
    const row = document.createElement('tr');
    cells.forEach((cell) => {
      const td = document.createElement('td');
      const isObject = cell !== null && typeof cell === 'object';
      td.textContent = isObject ? cell.value : cell;
      if (isObject) {
        if (cell.num) td.classList.add('num');
        if (cell.cls) td.classList.add(cell.cls);
      }
      row.appendChild(td);
    });
    tbody.appendChild(row);
  });

  el.append(thead, tbody);
  return el;
}

const pct = (v) => (v == null ? '—' : `${(v * 100).toFixed(1)}%`);
const fixed = (v, d) => (v == null ? '—' : Number(v).toFixed(d));
