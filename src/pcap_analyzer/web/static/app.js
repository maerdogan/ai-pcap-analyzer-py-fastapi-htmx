(function () {
  const words = JSON.parse(document.body.dataset.words || "{}");
  const t = (text) => words[text] || text;
  const secs = (v) => (v === null || v === undefined ? "–" : v < 1 ? (v * 1000).toFixed(1) + " ms" : v.toFixed(2) + " s");
  const bytes = (v) => {
    if (v === null || v === undefined) return "–";
    for (const u of ["B", "KB", "MB"]) { if (v < 1024) return (u === "B" ? v : v.toFixed(1)) + " " + u; v /= 1024; }
    return v.toFixed(1) + " GB";
  };
  const num = (field, headerName, extra) => ({ field, headerName, type: "numericColumn", width: 110, ...extra });
  const time = (field, headerName) => num(field, headerName, { valueFormatter: (p) => secs(p.value) });
  const size = (field, headerName) => num(field, headerName, { valueFormatter: (p) => bytes(p.value) });

  const GRIDS = {
    urls: (base) => ({
      columnDefs: [
        { field: "method", headerName: t("Method"), width: 95 },
        { field: "url", headerName: t("URL"), flex: 1, minWidth: 240, filter: true },
        num("requests", t("Requests")), num("failed", t("Failed"), { width: 90 }),
        time("avg_total", t("Average")), time("p95_total", t("95th pct")), time("max_total", t("Slowest")), time("avg_service", t("Service")),
        { headerName: t("Status"), width: 170, valueGetter: (p) => p.data.statuses.map((s) => (s.status || t("none")) + " ×" + s.requests).join(", ") },
      ],
      onRowClicked: (e) => { location.href = base + "/inspect?url=" + encodeURIComponent(e.data.url.split("{id}")[0]); },
    }),
    connections: (base) => ({
      columnDefs: [
        { headerName: t("Client"), width: 175, filter: true, valueGetter: (p) => p.data.client_ip + ":" + p.data.client_port },
        { headerName: t("Server"), width: 175, filter: true, valueGetter: (p) => p.data.server_ip + ":" + p.data.server_port },
        { field: "kind", headerName: t("Type"), width: 95, filter: true },
        num("requests", t("Requests"), { width: 100 }), time("avg_total", t("Average")), time("max_total", t("Slowest")), time("duration", t("Open for")),
        time("rtt_server", t("Round trip")), num("retransmissions", t("Retrans."), { width: 95 }), { field: "close_type", headerName: t("Closed"), width: 90 },
      ],
      onRowClicked: (e) => { location.href = base + "/conn/" + e.data.stream; },
    }),
    hosts: () => ({
      columnDefs: [
        { field: "host", headerName: t("Host"), flex: 1, minWidth: 220, filter: true },
        num("connections", t("Connections"), { width: 125 }), num("requests", t("Requests")), size("bytes", t("Bytes")),
        { headerName: t("Addresses"), flex: 1, valueGetter: (p) => (p.data.addresses || []).join(", ") },
      ],
    }),
  };

  function setupGrids(root) {
    root.querySelectorAll("[data-grid]").forEach(async (el) => {
      if (el.dataset.ready) return;
      el.dataset.ready = "1";
      const opts = GRIDS[el.dataset.grid](el.dataset.base);
      const rows = await (await fetch(el.dataset.src)).json();
      agGrid.createGrid(el, { ...opts, rowData: rows, defaultColDef: { sortable: true, resizable: true }, suppressCellFocus: true, rowHeight: 34, headerHeight: 36,
        rowClass: opts.onRowClicked ? "clickable" : undefined, domLayout: "normal" });
    });
  }

  const INK = "#202126", MUTED = "#5c616c", LINE = "#e4e8ee", BRAND = "#3347ee", GOOD = "#0b8540", BAD = "#c81e2b";
  function download(url, name) {
    Object.assign(document.createElement("a"), { href: url, download: name }).click();
  }
  function saveSvg(option, name, el) {
    const c = echarts.init(null, null, { renderer: "svg", ssr: true, width: el.clientWidth, height: el.clientHeight });
    c.setOption(option);
    const url = URL.createObjectURL(new Blob([c.renderToSVGString()], { type: "image/svg+xml" }));
    download(url, name + ".svg");
    URL.revokeObjectURL(url);
    c.dispose();
  }
  function chartButtons(el, chart, option) {
    const bar = document.createElement("p");
    bar.className = "chart-actions";
    const add = (label, onClick) => {
      const b = Object.assign(document.createElement("button"), { type: "button", textContent: label, className: "link" });
      b.addEventListener("click", onClick);
      bar.append(b);
    };
    add(t("Save as PNG"), () => download(chart.getDataURL({ type: "png", pixelRatio: 2, backgroundColor: "#ffffff" }), el.dataset.name + ".png"));
    add(t("Save as SVG"), () => saveSvg(option, el.dataset.name, el));
    el.after(bar);
  }
  const clock = (v) => new Date(v * 1000).toLocaleTimeString();
  const CHARTS = {
    timeline: (data) => {
      const times = data.rows.map((d) => clock(d.start));
      const line = (name, key, yAxisIndex, color) => ({ name, type: "line", yAxisIndex, showSymbol: false, data: data.rows.map((d) => d[key]), lineStyle: { color, width: 1.5 }, itemStyle: { color } });
      return {
        grid: { left: 48, right: 56, top: 34, bottom: 62 }, legend: { top: 0, icon: "roundRect", itemWidth: 12, itemHeight: 8 }, tooltip: { trigger: "axis" },
        dataZoom: [{ type: "slider", height: 18, bottom: 6 }],
        brush: { toolbox: ["lineX"], xAxisIndex: 0, brushMode: "single" },
        toolbox: { show: false },
        xAxis: { type: "category", data: times, axisLabel: { color: MUTED }, axisLine: { onZero: false, lineStyle: { color: LINE } } },
        yAxis: [{ type: "value", minInterval: 1, axisLabel: { color: MUTED, formatter: (v) => Math.abs(v) }, splitLine: { lineStyle: { color: LINE } } },
          { type: "value", axisLabel: { color: MUTED, formatter: (v) => secs(v) }, splitLine: { show: false } }],
        series: [
          // Errors hang below the axis, so a bad minute stands out against the traffic above it.
          { name: t("Requests"), type: "bar", data: data.rows.map((d) => d.requests), itemStyle: { color: BRAND, borderRadius: [3, 3, 0, 0] } },
          { name: t("Errors"), type: "bar", barGap: "-100%", data: data.rows.map((d) => -d.errors), itemStyle: { color: BAD, borderRadius: [0, 0, 3, 3] }, tooltip: { valueFormatter: (v) => Math.abs(v) } },
          line(t("Retransmissions"), "retransmissions", 0, "#a8489f"), line(t("Open connections"), "open_connections", 0, "#3e9b5f"),
          { ...line(t("95th percentile"), "p95_total", 1, "#e2702a"), connectNulls: false },
        ],
      };
    },
    histogram: (data) => ({
      grid: { left: 44, right: 12, top: 30, bottom: 56 }, tooltip: {},
      xAxis: { type: "category", data: data.map((d) => d.label), axisLabel: { rotate: 40, color: MUTED }, axisLine: { lineStyle: { color: LINE } } },
      yAxis: { type: "value", minInterval: 1, axisLabel: { color: MUTED }, splitLine: { lineStyle: { color: LINE } } },
      series: [{ type: "bar", data: data.map((d) => d.requests), itemStyle: { color: BRAND, borderRadius: [3, 3, 0, 0] }, barCategoryGap: "12%" }],
    }),
    statuses: (data) => ({
      grid: { left: 50, right: 12, top: 30, bottom: 28 }, tooltip: {},
      xAxis: { type: "value", minInterval: 1, axisLabel: { color: MUTED }, splitLine: { lineStyle: { color: LINE } } },
      yAxis: { type: "category", inverse: true, data: data.map((d) => d.class), axisLabel: { color: INK } },
      series: [{ type: "bar", data: data.map((d) => ({ value: d.requests,
        itemStyle: { color: /^[45]|none/.test(d.class) ? BAD : GOOD, borderRadius: [0, 3, 3, 0] } })) }],
    }),
  };

  const PHASE_COLORS = { connect_time: "#7b93ab", tls_time: "#7e6bc4", request_clean: "#1f9e8f", network: "#2f7fd1", queue_time: "#e0a82e", service: "#e2702a",
    transfer_clean: "#3e9b5f", retrans_time: "#c8324a", zero_window_time: "#a8489f", delayed_ack_time: "#96764a" };
  CHARTS.waterfall = (data) => ({
    grid: { left: 200, right: 16, top: 34, bottom: 28 }, legend: { top: 0, type: "scroll", icon: "roundRect", itemWidth: 12, itemHeight: 8 }, tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    xAxis: { type: "value", axisLabel: { color: MUTED, formatter: (v) => secs(v) }, splitLine: { lineStyle: { color: LINE } } },
    yAxis: { type: "category", inverse: true, data: data.rows.map((d) => d.label), axisLabel: { color: INK, width: 186, overflow: "truncate" } },
    series: [{ type: "bar", stack: "t", silent: true, itemStyle: { color: "transparent" }, data: data.rows.map((d) => d.start), tooltip: { show: false } }].concat(
      Object.keys(data.phases).map((p) => ({ name: data.phases[p], type: "bar", stack: "t", itemStyle: { color: PHASE_COLORS[p] }, data: data.rows.map((d) => d[p]), tooltip: { valueFormatter: secs } }))),
  });

  function rangeLink(el, chart, data) {
    const link = Object.assign(document.createElement("a"), { className: "button", hidden: true, textContent: t("Inspect this period") });
    el.parentElement.append(link);
    chart.dispatchAction({ type: "takeGlobalCursor", key: "brush", brushOption: { brushType: "lineX", brushMode: "single" } });
    chart.on("brushEnd", (e) => {
      const area = e.areas[0];
      link.hidden = !area;
      if (!area) return;
      const [first, last] = area.coordRange.map((i) => Math.min(Math.max(i, 0), data.rows.length - 1));
      link.href = `${el.dataset.base}/inspect?start=${data.rows[first].start}&end=${data.rows[last].start + data.width}`;
    });
  }

  function setupCharts(root) {
    root.querySelectorAll("[data-chart]").forEach(async (el) => {
      if (el.dataset.ready) return;
      el.dataset.ready = "1";
      const data = await (await fetch(el.dataset.src)).json();
      const chart = echarts.init(el, null, { renderer: "canvas" });
      const option = { textStyle: { fontFamily: "Archivo, system-ui, sans-serif" }, animation: false, ...CHARTS[el.dataset.chart](data) };
      chart.setOption(option);
      chartButtons(el, chart, option);
      if (el.dataset.chart === "timeline") rangeLink(el, chart, data);
      addEventListener("resize", () => chart.resize());
    });
  }

  function setup(root) {
    setupGrids(root);
    setupCharts(root);
    root.querySelectorAll("[data-submit]").forEach((el) => el.addEventListener("change", () => el.form.submit()));
  }
  document.addEventListener("DOMContentLoaded", () => {
    setup(document);
    document.body.addEventListener("htmx:afterSettle", (e) => setup(e.target));
    document.querySelector(".views [aria-current]")?.scrollIntoView({ inline: "center", block: "nearest" });
  });
})();
