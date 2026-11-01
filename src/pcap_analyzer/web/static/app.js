(function () {
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
        { field: "method", headerName: "Method", width: 95 },
        { field: "url", headerName: "URL", flex: 1, minWidth: 240, filter: true },
        num("requests", "Requests"), num("failed", "Failed", { width: 90 }),
        time("avg_total", "Average"), time("p95_total", "95th pct"), time("max_total", "Slowest"), time("avg_service", "Service"),
        { headerName: "Status", width: 170, valueGetter: (p) => p.data.statuses.map((s) => (s.status || "none") + " ×" + s.requests).join(", ") },
      ],
      onRowClicked: (e) => { location.href = base + "/inspect?url=" + encodeURIComponent(e.data.url.split("{id}")[0]); },
    }),
    connections: (base) => ({
      columnDefs: [
        { headerName: "Client", width: 175, filter: true, valueGetter: (p) => p.data.client_ip + ":" + p.data.client_port },
        { headerName: "Server", width: 175, filter: true, valueGetter: (p) => p.data.server_ip + ":" + p.data.server_port },
        { field: "kind", headerName: "Type", width: 95, filter: true },
        num("requests", "Requests", { width: 100 }), time("avg_total", "Average"), time("max_total", "Slowest"), time("duration", "Open for"),
        time("rtt_server", "Round trip"), num("retransmissions", "Retrans.", { width: 95 }), { field: "close_type", headerName: "Closed", width: 90 },
      ],
      onRowClicked: (e) => { location.href = base + "/conn/" + e.data.stream; },
    }),
    hosts: () => ({
      columnDefs: [
        { field: "host", headerName: "Host", flex: 1, minWidth: 220, filter: true },
        num("connections", "Connections", { width: 125 }), num("requests", "Requests"), size("bytes", "Bytes"),
        { headerName: "Addresses", flex: 1, valueGetter: (p) => (p.data.addresses || []).join(", ") },
      ],
    }),
  };

  function setupGrids(root) {
    root.querySelectorAll("[data-grid]").forEach(async (el) => {
      if (el.dataset.ready) return;
      el.dataset.ready = "1";
      const opts = GRIDS[el.dataset.grid](el.dataset.base);
      const rows = await (await fetch(el.dataset.src)).json();
      agGrid.createGrid(el, { ...opts, rowData: rows, defaultColDef: { sortable: true, resizable: true }, suppressCellFocus: true,
        rowClass: opts.onRowClicked ? "clickable" : undefined });
    });
  }

  const INK = "#14263a", MUTED = "#55677a", LINE = "#c9d3db";
  function saveSvg(option, name, el) {
    const c = echarts.init(null, null, { renderer: "svg", ssr: true, width: el.clientWidth, height: el.clientHeight });
    c.setOption(option);
    const url = URL.createObjectURL(new Blob([c.renderToSVGString()], { type: "image/svg+xml" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: name + ".svg" });
    a.click();
    URL.revokeObjectURL(url);
    c.dispose();
  }
  const tools = (name) => ({ right: 0, feature: {
    saveAsImage: { name, title: "Save as PNG", backgroundColor: "#edf1f4" },
    mySvg: { show: true, title: "Save as SVG", icon: "path://M4 4h16v16H4z", onclick: (m, api) => saveSvg(api.getOption(), name, api.getDom()) },
  } });
  const CHARTS = {
    histogram: (data, name) => ({
      toolbox: tools(name), grid: { left: 44, right: 12, top: 30, bottom: 56 }, tooltip: {},
      xAxis: { type: "category", data: data.map((d) => d.label), axisLabel: { rotate: 40, color: MUTED }, axisLine: { lineStyle: { color: LINE } } },
      yAxis: { type: "value", minInterval: 1, axisLabel: { color: MUTED }, splitLine: { lineStyle: { color: LINE } } },
      series: [{ type: "bar", data: data.map((d) => d.requests), itemStyle: { color: "#1f7fbf" }, barCategoryGap: "12%" }],
    }),
    statuses: (data, name) => ({
      toolbox: tools(name), grid: { left: 50, right: 12, top: 30, bottom: 28 }, tooltip: {},
      xAxis: { type: "value", minInterval: 1, axisLabel: { color: MUTED }, splitLine: { lineStyle: { color: LINE } } },
      yAxis: { type: "category", inverse: true, data: data.map((d) => d.class), axisLabel: { color: INK } },
      series: [{ type: "bar", data: data.map((d) => ({ value: d.requests,
        itemStyle: { color: /^[45]|none/.test(d.class) ? "#c4314b" : "#4f9d4f" } })) }],
    }),
  };

  function setupCharts(root) {
    root.querySelectorAll("[data-chart]").forEach(async (el) => {
      if (el.dataset.ready) return;
      el.dataset.ready = "1";
      const data = await (await fetch(el.dataset.src)).json();
      const chart = echarts.init(el, null, { renderer: "canvas" });
      chart.setOption({ textStyle: { fontFamily: "Archivo, system-ui, sans-serif" }, animation: false, ...CHARTS[el.dataset.chart](data, el.dataset.name) });
      addEventListener("resize", () => chart.resize());
    });
  }

  function setup(root) { setupGrids(root); setupCharts(root); }
  document.addEventListener("DOMContentLoaded", () => {
    setup(document);
    document.body.addEventListener("htmx:afterSettle", (e) => setup(e.target));
  });
})();
