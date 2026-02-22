
const { useEffect, useMemo, useRef, useState } = React;

function App() {
  const [branding, setBranding] = useState({ app_name: "InfraTrack", logo_url: null });
  const [accessToken, setAccessToken] = useState(localStorage.getItem("itam_access") || "");
  const [refreshToken, setRefreshToken] = useState(localStorage.getItem("itam_refresh") || "");
  const [me, setMe] = useState(null);
  const [mustChangePassword, setMustChangePassword] = useState(false);

  const [view, setView] = useState("dashboard");
  const [loginForm, setLoginForm] = useState({ username: "", password: "" });
  const [passwordForm, setPasswordForm] = useState({ old_password: "", new_password: "" });

  const [dashboard, setDashboard] = useState(null);
  const [masters, setMasters] = useState({ assetTypes: [], statuses: [], departments: [], locations: [], manufacturers: [], vendors: [] });

  const [assetRows, setAssetRows] = useState([]);
  const [assetFilter, setAssetFilter] = useState({ q: "", status_filter: "", limit: 200 });

  const [selectedAsset, setSelectedAsset] = useState(null);
  const [assetEdit, setAssetEdit] = useState(null);
  const [timeline, setTimeline] = useState([]);

  const [selectedUser, setSelectedUser] = useState(null);

  const [assetForm, setAssetForm] = useState({
    asset_type: "", serial_number: "", manufacturer: "", model: "",
    purchase_date: todayISO(), warranty_start: todayISO(), warranty_end: addDaysISO(365),
    vendor: "", cost: "", location: "", department: "", status: "InStock",
  });

  const [assignForm, setAssignForm] = useState({
    asset_code: "", assignee_name: "", assignee_email: "", assignee_phone: "", assignee_emp_id: "",
    department: "", location: "", expected_return: "", remarks: "",
  });

  const [users, setUsers] = useState([]);
  const [idForm, setIdForm] = useState({ username: "", email: "", password: "", role: "ITUser" });
  const [bulkFile, setBulkFile] = useState(null);
  const [lastCreatedAssetId, setLastCreatedAssetId] = useState("");
  const [reportDays, setReportDays] = useState(60);

  const [toast, setToast] = useState({ open: false, message: "", type: "info" });
  const toastTimer = useRef(null);
  const refreshPromiseRef = useRef(null);

  const authed = !!accessToken;
  const isAdmin = me?.role === "Admin";

  useEffect(() => {
    if (!authed) return;
    boot();
  }, [authed]);

  useEffect(() => {
    loadBranding();
  }, []);

  useEffect(() => () => clearToastTimer(), []);

  async function boot() {
    const profile = await fetchMe();
    if (!profile) return;
    await Promise.all([loadMasters(), fetchDashboard(), fetchAssetRows()]);
  }

  async function loadBranding() {
    try {
      const res = await fetch("/branding");
      if (!res.ok) return;
      const data = await res.json();
      setBranding({
        app_name: data.app_name || "InfraTrack",
        logo_url: data.logo_url || null,
      });
    } catch {
      // Keep defaults when branding API is unavailable.
    }
  }

  function clearToastTimer() {
    if (toastTimer.current) {
      clearTimeout(toastTimer.current);
      toastTimer.current = null;
    }
  }

  function showToast(message, type = "info", ms = 3500) {
    clearToastTimer();
    setToast({ open: true, message, type });
    toastTimer.current = setTimeout(() => setToast((t) => ({ ...t, open: false })), ms);
  }

  async function apiFetch(path, options = {}, allowRefresh = true) {
    const headers = { ...(options.headers || {}) };
    if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
    const res = await fetch(path, { ...options, headers });
    if (res.status === 401 && allowRefresh && refreshToken) {
      const ok = await refreshAccess();
      if (ok) return apiFetch(path, options, false);
    }
    return res;
  }

  async function refreshAccess() {
    if (refreshPromiseRef.current) {
      return refreshPromiseRef.current;
    }
    refreshPromiseRef.current = (async () => {
    try {
      const res = await fetch("/auth/refresh", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
      if (!res.ok) { logoutLocal(); return false; }
      const data = await res.json();
      localStorage.setItem("itam_access", data.access_token);
      localStorage.setItem("itam_refresh", data.refresh_token);
      setAccessToken(data.access_token);
      setRefreshToken(data.refresh_token);
      setMustChangePassword(!!data.must_change_password);
      return true;
    } catch {
      logoutLocal();
      return false;
    } finally {
      refreshPromiseRef.current = null;
    }
    })();
    return refreshPromiseRef.current;
  }

  async function fetchMe() {
    const res = await apiFetch("/auth/me");
    if (!res.ok) return null;
    const profile = await res.json();
    setMe(profile);
    setMustChangePassword(!!profile.must_change_password);
    return profile;
  }

  async function login(e) {
    e.preventDefault();
    const body = new URLSearchParams();
    body.set("username", loginForm.username);
    body.set("password", loginForm.password);
    const res = await fetch("/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    if (!res.ok) return showToast(`Login failed: ${await safeDetail(res)}`, "error", 5000);
    const data = await res.json();
    localStorage.setItem("itam_access", data.access_token);
    localStorage.setItem("itam_refresh", data.refresh_token);
    setAccessToken(data.access_token);
    setRefreshToken(data.refresh_token);
    setMustChangePassword(!!data.must_change_password);
    showToast("Login successful", "success");
  }

  function logoutLocal() {
    localStorage.removeItem("itam_access");
    localStorage.removeItem("itam_refresh");
    setAccessToken("");
    setRefreshToken("");
    setMustChangePassword(false);
    setMe(null);
    setDashboard(null);
    setAssetRows([]);
    setSelectedAsset(null);
    setAssetEdit(null);
    setTimeline([]);
    setSelectedUser(null);
    setUsers([]);
    setView("dashboard");
  }

  function logout() {
    logoutLocal();
    showToast("Logged out", "info");
  }

  async function submitPasswordChange(e) {
    e.preventDefault();
    const res = await apiFetch("/auth/change-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(passwordForm),
    });
    if (!res.ok) return showToast(`Password change failed: ${await safeDetail(res)}`, "error", 6000);
    setMustChangePassword(false);
    setPasswordForm({ old_password: "", new_password: "" });
    showToast("Password updated", "success");
    fetchMe();
  }

  async function loadMasters() {
    const [assetTypes, statuses, departments, locations, manufacturers, vendors] = await Promise.all([
      apiFetch("/masters/asset-types"),
      apiFetch("/masters/statuses"),
      apiFetch("/masters/departments"),
      apiFetch("/masters/locations"),
      apiFetch("/masters/manufacturers"),
      apiFetch("/masters/vendors"),
    ]);

    const data = {
      assetTypes: assetTypes.ok ? await assetTypes.json() : [],
      statuses: statuses.ok ? await statuses.json() : [],
      departments: departments.ok ? await departments.json() : [],
      locations: locations.ok ? await locations.json() : [],
      manufacturers: manufacturers.ok ? await manufacturers.json() : [],
      vendors: vendors.ok ? await vendors.json() : [],
    };
    setMasters(data);

    setAssetForm((prev) => ({
      ...prev,
      asset_type: prev.asset_type || data.assetTypes[0]?.name || "",
      status: prev.status || data.statuses[0]?.name || "InStock",
      department: prev.department || data.departments[0]?.name || "",
      location: prev.location || data.locations[0]?.name || "",
      manufacturer: prev.manufacturer || data.manufacturers[0]?.name || "",
      vendor: prev.vendor || data.vendors[0]?.name || "",
    }));

    setAssignForm((prev) => ({
      ...prev,
      department: prev.department || data.departments[0]?.name || "",
      location: prev.location || data.locations[0]?.name || "",
    }));
  }

  async function fetchDashboard() {
    const res = await apiFetch("/dashboard/summary");
    if (!res.ok) return;
    setDashboard(await res.json());
  }

  async function reprintQr(assetCode) {
    if (!assetCode) return;
    const res = await apiFetch(`/assets/${encodeURIComponent(assetCode)}/qr`);
    if (!res.ok) return showToast(`QR print failed: ${await safeDetail(res)}`, "error", 6000);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank");
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }

  function toQuery(params) {
    const usp = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== null && v !== undefined && String(v).trim() !== "") usp.set(k, v);
    });
    return usp.toString();
  }

  async function fetchAssetRows(filter = assetFilter) {
    const res = await apiFetch(`/assets/table?${toQuery(filter)}`);
    if (!res.ok) return showToast(`Asset load failed: ${await safeDetail(res)}`, "error");
    setAssetRows(await res.json());
  }

  async function openAsset(assetCode) {
    const [assetRes, timelineRes] = await Promise.all([
      apiFetch(`/assets/${encodeURIComponent(assetCode)}`),
      apiFetch(`/assets/${encodeURIComponent(assetCode)}/timeline`),
    ]);
    if (!assetRes.ok) return showToast(`Asset load failed: ${await safeDetail(assetRes)}`, "error");
    const asset = await assetRes.json();
    setSelectedAsset(asset);
    setAssetEdit({ ...asset });
    setAssignForm((f) => ({ ...f, asset_code: asset.asset_id }));
    if (timelineRes.ok) setTimeline(await timelineRes.json());
    else setTimeline([]);
    setView("asset_detail");
  }

  async function openUser(userName) {
    if (!userName) return;
    const res = await apiFetch(`/assignees/${encodeURIComponent(userName)}`);
    if (!res.ok) return showToast(`User detail failed: ${await safeDetail(res)}`, "error");
    setSelectedUser(await res.json());
    setView("user_detail");
  }
  async function saveAsset() {
    if (!assetEdit) return;
    const payload = isAdmin
      ? {
          asset_type: assetEdit.asset_type,
          serial_number: assetEdit.serial_number,
          manufacturer: assetEdit.manufacturer,
          model: assetEdit.model,
          purchase_date: assetEdit.purchase_date,
          warranty_start: assetEdit.warranty_start,
          warranty_end: assetEdit.warranty_end,
          vendor: assetEdit.vendor,
          cost: assetEdit.cost === "" ? null : Number(assetEdit.cost),
          location: assetEdit.location,
          department: assetEdit.department,
          status: assetEdit.status,
        }
      : {
          location: assetEdit.location,
        };
    const res = await apiFetch(`/assets/${encodeURIComponent(assetEdit.asset_id)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) return showToast(`Asset update failed: ${await safeDetail(res)}`, "error", 6000);
    showToast("Asset updated", "success");
    await openAsset(assetEdit.asset_id);
    fetchAssetRows();
    fetchDashboard();
  }

  async function lifecycle(action) {
    if (!selectedAsset) return;
    const remarks = (prompt(`Remarks for ${action.replace('_', ' ')} action`) || "").trim();
    if (!remarks) return showToast("Remarks are mandatory", "error");
    const res = await apiFetch(`/assets/${selectedAsset.id}/lifecycle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action, remarks }),
    });
    if (!res.ok) return showToast(`Lifecycle update failed: ${await safeDetail(res)}`, "error", 6000);
    showToast(`Asset marked as ${action}`, "success");
    await openAsset(selectedAsset.asset_id);
    fetchAssetRows();
    fetchDashboard();
  }

  async function createAsset(e) {
    e.preventDefault();
    const payload = { ...assetForm, cost: assetForm.cost === "" ? null : Number(assetForm.cost) };
    const res = await apiFetch("/assets/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) return showToast(`Create asset failed: ${await safeDetail(res)}`, "error", 6000);
    const created = await res.json();
    showToast(`Asset created: ${created.asset_id}`, "success");
    setLastCreatedAssetId(created.asset_id);
    setAssetForm((p) => ({ ...p, serial_number: "", model: "", cost: "" }));
    fetchDashboard();
    fetchAssetRows();
  }

  async function uploadBulk(e) {
    e.preventDefault();
    if (!bulkFile) return showToast("Select CSV/XLSX file", "info");
    const fd = new FormData();
    fd.append("file", bulkFile);
    const res = await apiFetch("/assets/bulk-upload", { method: "POST", body: fd });
    if (!res.ok) return showToast(`Bulk upload failed: ${await safeDetail(res)}`, "error", 6000);
    const out = await res.json();
    if (out.failed > 0) {
      const topErrors = (out.errors || [])
        .slice(0, 3)
        .map((x) => `Line ${x.line}: ${x.error}`)
        .join(" | ");
      showToast(`Bulk upload complete. Created ${out.created}, Failed ${out.failed}. ${topErrors}`, "error", 10000);
    } else {
      showToast(`Bulk upload complete. Created ${out.created}, Failed ${out.failed}`, "success", 6000);
    }
    fetchDashboard();
    fetchAssetRows();
  }

  async function downloadSampleCsv() {
    const res = await apiFetch("/assets/sample-template.csv");
    if (!res.ok) return showToast(`Template download failed: ${await safeDetail(res)}`, "error", 6000);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "asset_bulk_upload_template.csv";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }

  async function downloadReport(path, filename) {
    const res = await apiFetch(path);
    if (!res.ok) return showToast(`Report download failed: ${await safeDetail(res)}`, "error", 6000);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }

  async function resolveAssetId(assetCode) {
    const res = await apiFetch(`/assets/${encodeURIComponent((assetCode || "").trim())}`);
    if (!res.ok) throw new Error(await safeDetail(res));
    const asset = await res.json();
    return { id: asset.id, code: asset.asset_id };
  }

  async function assignAsset(e) {
    e.preventDefault();
    if (!assignForm.asset_code.trim()) return showToast("Asset ID required", "error");
    if (!assignForm.assignee_name.trim()) return showToast("User Name required", "error");
    if (!assignForm.department.trim() || !assignForm.location.trim()) return showToast("Department and Location required", "error");
    if (!assignForm.remarks.trim()) return showToast("Remarks are mandatory", "error");

    try {
      const asset = await resolveAssetId(assignForm.asset_code);
      const payload = {
        asset_id: asset.id,
        assignee_name: assignForm.assignee_name,
        assignee_email: assignForm.assignee_email || null,
        assignee_phone: assignForm.assignee_phone || null,
        assignee_emp_id: assignForm.assignee_emp_id || null,
        department: assignForm.department,
        location: assignForm.location,
        expected_return: assignForm.expected_return || null,
        remarks: assignForm.remarks.trim(),
      };
      const res = await apiFetch("/assignments/assign", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error(await safeDetail(res));
      showToast("Asset assigned", "success");
      fetchDashboard();
      fetchAssetRows();
      if (view === "asset_detail" && selectedAsset?.asset_id === asset.code) openAsset(asset.code);
    } catch (err) {
      showToast(`Assignment failed: ${err.message || err}`, "error", 6000);
    }
  }

  async function returnAssetByCode(assetCode, remarks) {
    if (!remarks || !remarks.trim()) throw new Error("Remarks are mandatory");
    const asset = await resolveAssetId(assetCode);
    const fd = new FormData();
    fd.append("remarks", remarks.trim());
    const res = await apiFetch(`/assignments/${asset.id}/return`, { method: "POST", body: fd });
    if (!res.ok) throw new Error(await safeDetail(res));
    return asset.code;
  }

  async function repairAssetByCode(assetCode, remarks) {
    if (!remarks || !remarks.trim()) throw new Error("Remarks are mandatory");
    const asset = await resolveAssetId(assetCode);
    const fd = new FormData();
    fd.append("remarks", remarks.trim());
    const res = await apiFetch(`/assignments/${asset.id}/repair`, { method: "POST", body: fd });
    if (!res.ok) throw new Error(await safeDetail(res));
    return asset.code;
  }

  async function returnAsset() {
    if (!assignForm.asset_code.trim()) return showToast("Asset ID required", "error");
    if (!assignForm.remarks.trim()) return showToast("Remarks are mandatory", "error");
    try {
      const code = await returnAssetByCode(assignForm.asset_code, assignForm.remarks);
      showToast("Asset returned", "success");
      fetchDashboard();
      fetchAssetRows();
      if (view === "asset_detail" && selectedAsset?.asset_id === code) openAsset(code);
    } catch (err) {
      showToast(`Return failed: ${err.message || err}`, "error", 6000);
    }
  }

  async function markRepair() {
    if (!assignForm.asset_code.trim()) return showToast("Asset ID required", "error");
    if (!assignForm.remarks.trim()) return showToast("Remarks are mandatory", "error");
    try {
      const code = await repairAssetByCode(assignForm.asset_code, assignForm.remarks);
      showToast("Asset moved to repair", "success");
      fetchDashboard();
      fetchAssetRows();
      if (view === "asset_detail" && selectedAsset?.asset_id === code) openAsset(code);
    } catch (err) {
      showToast(`Repair failed: ${err.message || err}`, "error", 6000);
    }
  }

  async function loadUsers() {
    if (!isAdmin) return;
    const res = await apiFetch("/users/");
    if (!res.ok) return showToast(`Users load failed: ${await safeDetail(res)}`, "error");
    setUsers(await res.json());
  }

  async function createId(e) {
    e.preventDefault();
    const res = await apiFetch("/users/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(idForm),
    });
    if (!res.ok) return showToast(`Create ID failed: ${await safeDetail(res)}`, "error", 6000);
    showToast("User created. Must change password on first login.", "success");
    setIdForm({ username: "", email: "", password: "", role: "ITUser" });
    loadUsers();
  }

  async function deleteId(id) {
    if (!confirm("Deactivate this user?")) return;
    const res = await apiFetch(`/users/${id}`, { method: "DELETE" });
    if (!res.ok) return showToast(`Deactivate failed: ${await safeDetail(res)}`, "error");
    showToast("User deactivated", "success");
    loadUsers();
  }

  async function uploadLogo(e) {
    e.preventDefault();
    const file = e.target?.elements?.logo_file?.files?.[0];
    if (!file) return showToast("Select a logo file", "info");
    const fd = new FormData();
    fd.append("file", file);
    const res = await apiFetch("/branding/logo", { method: "POST", body: fd });
    if (!res.ok) return showToast(`Logo upload failed: ${await safeDetail(res)}`, "error", 6000);
    const data = await res.json();
    setBranding({
      app_name: data.app_name || "InfraTrack",
      logo_url: data.logo_url || null,
    });
    showToast("Company logo updated", "success");
    e.target.reset();
  }

  const dashboardCards = useMemo(() => {
    if (!dashboard) return [];
    return [
      { key: "ALL", label: "Assets", value: dashboard.total_assets },
      { key: "InStock", label: "Ready to Deploy", value: dashboard.unassigned_assets },
      { key: "Assigned", label: "Assigned", value: dashboard.assigned_assets },
      { key: "UnderRepair", label: "Under Repair", value: dashboard.under_repair_assets },
    ];
  }, [dashboard]);

  function drillStatus(statusKey) {
    setView("assets");
    const next = { ...assetFilter, status_filter: statusKey === "ALL" ? "" : statusKey };
    setAssetFilter(next);
    fetchAssetRows(next);
  }
  if (!authed) {
    return (
      <main className="s-login-wrap">
        <section className="s-login-card">
          <div className="s-branding">
            {branding.logo_url && <img className="s-logo" src={branding.logo_url} alt="Company Logo" />}
            <h1>{branding.app_name || "InfraTrack"}</h1>
          </div>
          <p>Sign in to continue</p>
          <form onSubmit={login}>
            <input placeholder="Username" value={loginForm.username} onChange={(e) => setLoginForm({ ...loginForm, username: e.target.value })} required />
            <input type="password" placeholder="Password" value={loginForm.password} onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })} required />
            <button type="submit">Login</button>
          </form>
        </section>
        {toast.open && <Toast toast={toast} onClose={() => setToast((t) => ({ ...t, open: false }))} />}
      </main>
    );
  }

  if (mustChangePassword) {
    return (
      <main className="s-login-wrap">
        <section className="s-login-card">
          <h1>Change Password</h1>
          <p>Required before first use.</p>
          <form onSubmit={submitPasswordChange}>
            <input type="password" placeholder="Current Password" value={passwordForm.old_password} onChange={(e) => setPasswordForm({ ...passwordForm, old_password: e.target.value })} required />
            <input type="password" placeholder="New Password" value={passwordForm.new_password} onChange={(e) => setPasswordForm({ ...passwordForm, new_password: e.target.value })} required />
            <button type="submit">Update Password</button>
          </form>
        </section>
        {toast.open && <Toast toast={toast} onClose={() => setToast((t) => ({ ...t, open: false }))} />}
      </main>
    );
  }

  return (
    <main className="s-app">
      <aside className="s-sidebar">
        <div className="s-branding s-branding-sidebar">
          {branding.logo_url && <img className="s-logo s-logo-small" src={branding.logo_url} alt="Company Logo" />}
          <div className="s-brand">{branding.app_name || "InfraTrack"}</div>
        </div>
        <button className={view === "dashboard" ? "on" : ""} onClick={() => setView("dashboard")}>Dashboard</button>
        <button className={view === "assets" ? "on" : ""} onClick={() => setView("assets")}>Assets</button>
        <button className={view === "create" ? "on" : ""} onClick={() => setView("create")}>Create Asset</button>
        <button className={view === "assignment" ? "on" : ""} onClick={() => setView("assignment")}>Asset Assignment</button>
        <button className={view === "reports" ? "on" : ""} onClick={() => setView("reports")}>Reports</button>
        {isAdmin && <button className={view === "ids" ? "on" : ""} onClick={() => { setView("ids"); loadUsers(); }}>Users</button>}
      </aside>

      <section className="s-main">
        <header className="s-top">
          <div>
            <h2>{view === "dashboard" ? "Overview" : view === "assets" ? "Asset Directory" : view === "create" ? "Asset Intake" : view === "assignment" ? "Asset Assignment" : view === "reports" ? "Reports" : view === "asset_detail" ? "Asset Details" : view === "user_detail" ? "User Details" : "User Administration"}</h2>
            <p>{me?.username} ({me?.role})</p>
          </div>
          <div className="s-actions-inline">
            <button className="s-ghost s-btn-compact" onClick={() => setView("reports")}>Reports</button>
            <button className="s-ghost s-btn-compact" onClick={logout}>Logout</button>
          </div>
        </header>

        {view === "dashboard" && (
          <section className="s-panel">
            <div className="s-metrics">
              {dashboardCards.map((k) => (
                <button key={k.key} className="s-metric" onClick={() => drillStatus(k.key)}>
                  <span>{k.label}</span>
                  <strong>{k.value}</strong>
                </button>
              ))}
            </div>
            <div className="s-actions-inline">
              <button className="s-ghost s-btn-compact" onClick={() => setView("reports")}>Open Reports</button>
            </div>
          </section>
        )}

        {view === "assets" && (
          <section className="s-panel">
            <div className="s-toolbar">
              <input placeholder="Search asset/serial/model/user" value={assetFilter.q} onChange={(e) => setAssetFilter({ ...assetFilter, q: e.target.value })} />
              <select value={assetFilter.status_filter} onChange={(e) => setAssetFilter({ ...assetFilter, status_filter: e.target.value })}>
                <option value="">All Status</option>
                {masters.statuses.map((s) => <option key={s.id} value={s.name}>{s.name}</option>)}
              </select>
              <button onClick={() => fetchAssetRows()}>Filter</button>
            </div>
            <table className="s-table">
              <thead>
                <tr><th>Asset ID</th><th>Type</th><th>Model</th><th>Status</th><th>Assigned To</th><th>Location</th></tr>
              </thead>
              <tbody>
                {assetRows.map((a) => (
                  <tr key={a.id}>
                    <td><button className="link-btn" onClick={() => openAsset(a.asset_id)}>{a.asset_id}</button></td>
                    <td>{a.asset_type}</td>
                    <td>{a.manufacturer} {a.model}</td>
                    <td>{a.status}</td>
                    <td>{a.assignee_name ? <button className="link-btn" onClick={() => openUser(a.assignee_name)}>{a.assignee_name}</button> : "-"}</td>
                    <td>{a.location}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        )}

        {view === "asset_detail" && selectedAsset && assetEdit && (
          <section className="s-panel s-grid2">
            <div>
              <h3>{selectedAsset.asset_id}</h3>
              {!isAdmin && <p className="s-hint">Only location can be edited by IT User. All other asset fields are Admin-only.</p>}
              <form className="s-form" onSubmit={(e) => { e.preventDefault(); saveAsset(); }}>
                <label>Asset Type<select disabled={!isAdmin} value={assetEdit.asset_type} onChange={(e) => setAssetEdit({ ...assetEdit, asset_type: e.target.value })}>{masters.assetTypes.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</select></label>
                <label>Serial Number<input disabled={!isAdmin} value={assetEdit.serial_number} onChange={(e) => setAssetEdit({ ...assetEdit, serial_number: e.target.value })} /></label>
                <label>Manufacturer<select disabled={!isAdmin} value={assetEdit.manufacturer} onChange={(e) => setAssetEdit({ ...assetEdit, manufacturer: e.target.value })}>{masters.manufacturers.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</select></label>
                <label>Model<input disabled={!isAdmin} value={assetEdit.model} onChange={(e) => setAssetEdit({ ...assetEdit, model: e.target.value })} /></label>
                <label>Purchase Date<input disabled={!isAdmin} type="date" value={assetEdit.purchase_date} onChange={(e) => setAssetEdit({ ...assetEdit, purchase_date: e.target.value })} /></label>
                <label>Warranty End<input disabled={!isAdmin} type="date" value={assetEdit.warranty_end} onChange={(e) => setAssetEdit({ ...assetEdit, warranty_end: e.target.value })} /></label>
                <label>Department<select disabled={!isAdmin} value={assetEdit.department} onChange={(e) => setAssetEdit({ ...assetEdit, department: e.target.value })}>{masters.departments.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</select></label>
                <label>Location<select value={assetEdit.location} onChange={(e) => setAssetEdit({ ...assetEdit, location: e.target.value })}>{masters.locations.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</select></label>
                <label>Status<select disabled={!isAdmin} value={assetEdit.status} onChange={(e) => setAssetEdit({ ...assetEdit, status: e.target.value })}>{masters.statuses.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</select></label>
                <button type="submit">Save Asset</button>
              </form>
              <div className="s-actions-inline">
                <button className="s-ghost" onClick={async () => { const r = (prompt("Remarks for moving asset to inventory") || "").trim(); if (!r) { showToast("Remarks are mandatory", "error"); return; } try { await returnAssetByCode(selectedAsset.asset_id, r); showToast("Moved to inventory", "success"); openAsset(selectedAsset.asset_id); fetchAssetRows(); fetchDashboard(); } catch (e) { showToast(`Action failed: ${e.message || e}`, "error"); } }}>Move to Inventory</button>
                <button className="s-warn" onClick={async () => { const r = (prompt("Remarks for moving asset to repair") || "").trim(); if (!r) { showToast("Remarks are mandatory", "error"); return; } try { await repairAssetByCode(selectedAsset.asset_id, r); showToast("Moved to repair", "success"); openAsset(selectedAsset.asset_id); fetchAssetRows(); fetchDashboard(); } catch (e) { showToast(`Action failed: ${e.message || e}`, "error"); } }}>Move to Repair</button>
                <button className="s-ghost" onClick={() => reprintQr(selectedAsset.asset_id)}>Reprint QR</button>
                {isAdmin && <button className="s-danger" onClick={() => lifecycle("scrap")}>Scrap</button>}
                {isAdmin && <button className="s-danger" onClick={() => lifecycle("end_of_life")}>End of Life</button>}
                {isAdmin && <button className="s-danger" onClick={() => lifecycle("lost")}>Mark Lost</button>}
              </div>
            </div>
            <div>
              <h3>Timeline</h3>
              <div className="s-timeline">
                {timeline.map((ev, i) => (
                  <div key={i} className="s-event">
                    <div className="s-muted"><strong>{formatIST(ev.timestamp)}</strong> - {ev.event_type}</div>
                    <div>{ev.details}</div>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}
        {view === "user_detail" && selectedUser && (
          <section className="s-panel s-grid2">
            <div>
              <h3>{selectedUser.user_name}</h3>
              <p className="s-hint">Email: {selectedUser.email || "-"}</p>
              <p className="s-hint">Phone: {selectedUser.phone || "-"}</p>
              <p className="s-hint">Employee ID: {selectedUser.emp_id || "-"}</p>

              <h4>Currently Assigned</h4>
              <div className="s-userlist">
                {selectedUser.current_assets.map((row, idx) => (
                  <div key={`${row.asset?.id || idx}-current`} className="s-userrow">
                    <button className="link-btn" onClick={() => openAsset(row.asset.asset_id)}>{row.asset.asset_id}</button> - {row.asset.asset_type} - {row.asset.status}
                    <div className="s-muted">Assigned: {formatIST(row.assigned_at)}</div>
                  </div>
                ))}
                {selectedUser.current_assets.length === 0 && <div className="s-muted">No current assignments</div>}
              </div>
            </div>
            <div>
              <h4>Historical Assignments</h4>
              <div className="s-userlist">
                {selectedUser.historical_assets.map((row, idx) => (
                  <div key={`${row.asset?.id || idx}-history-${row.assigned_at || ""}`} className="s-userrow">
                    <button className="link-btn" onClick={() => openAsset(row.asset.asset_id)}>{row.asset.asset_id}</button> - {row.asset.asset_type} - {row.asset.status}
                    <div className="s-muted">Assigned: {formatIST(row.assigned_at)}</div>
                    <div className="s-muted">Closed: {row.closed_at ? formatIST(row.closed_at) : "-"} {row.closed_event ? `(${row.closed_event})` : ""}</div>
                  </div>
                ))}
                {selectedUser.historical_assets.length === 0 && <div className="s-muted">No assignment history found</div>}
              </div>
            </div>
          </section>
        )}

        {view === "create" && (
          <section className="s-panel s-grid2">
            <form className="s-form" onSubmit={createAsset}>
              <label>Asset Type<select value={assetForm.asset_type} onChange={(e) => setAssetForm({ ...assetForm, asset_type: e.target.value })}>{masters.assetTypes.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</select></label>
              <label>Serial Number<input value={assetForm.serial_number} onChange={(e) => setAssetForm({ ...assetForm, serial_number: e.target.value })} required /></label>
              <label>Manufacturer<select value={assetForm.manufacturer} onChange={(e) => setAssetForm({ ...assetForm, manufacturer: e.target.value })}>{masters.manufacturers.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</select></label>
              <label>Model<input value={assetForm.model} onChange={(e) => setAssetForm({ ...assetForm, model: e.target.value })} required /></label>
              <label>Vendor<select value={assetForm.vendor} onChange={(e) => setAssetForm({ ...assetForm, vendor: e.target.value })}>{masters.vendors.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</select></label>
              <label>Cost<input type="number" step="0.01" value={assetForm.cost} onChange={(e) => setAssetForm({ ...assetForm, cost: e.target.value })} /></label>
              <label>Purchase Date<input type="date" value={assetForm.purchase_date} onChange={(e) => setAssetForm({ ...assetForm, purchase_date: e.target.value })} required /></label>
              <label>Warranty Start<input type="date" value={assetForm.warranty_start} onChange={(e) => setAssetForm({ ...assetForm, warranty_start: e.target.value })} required /></label>
              <label>Warranty End<input type="date" value={assetForm.warranty_end} onChange={(e) => setAssetForm({ ...assetForm, warranty_end: e.target.value })} required /></label>
              <label>Department<select value={assetForm.department} onChange={(e) => setAssetForm({ ...assetForm, department: e.target.value })}>{masters.departments.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</select></label>
              <label>Location<select value={assetForm.location} onChange={(e) => setAssetForm({ ...assetForm, location: e.target.value })}>{masters.locations.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</select></label>
              <label>Status<select value={assetForm.status} onChange={(e) => setAssetForm({ ...assetForm, status: e.target.value })}>{masters.statuses.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</select></label>
              <button type="submit">Create Asset</button>
            </form>
            <div className="s-panel-inset">
              <h3>Bulk Upload</h3>
              {lastCreatedAssetId && (
                <div className="s-actions-inline">
                  <button className="s-ghost" type="button" onClick={() => reprintQr(lastCreatedAssetId)}>Reprint Last QR</button>
                </div>
              )}
              <form onSubmit={uploadBulk}>
                <input type="file" accept=".csv,.xlsx" onChange={(e) => setBulkFile(e.target.files?.[0] || null)} />
                <div className="s-actions-inline">
                  <button type="submit">Upload</button>
                  <button className="s-ghost" type="button" onClick={downloadSampleCsv}>Download Sample CSV</button>
                </div>
              </form>
            </div>
          </section>
        )}

        {view === "assignment" && (
          <section className="s-panel s-grid2">
            <form className="s-form s-form-compact s-assignment-form" onSubmit={assignAsset}>
              <label>Asset ID<input value={assignForm.asset_code} onChange={(e) => setAssignForm({ ...assignForm, asset_code: e.target.value })} required /></label>
              <label>User Name<input value={assignForm.assignee_name} onChange={(e) => setAssignForm({ ...assignForm, assignee_name: e.target.value })} required /></label>
              <label>Email<input value={assignForm.assignee_email} onChange={(e) => setAssignForm({ ...assignForm, assignee_email: e.target.value })} /></label>
              <label>Phone<input value={assignForm.assignee_phone} onChange={(e) => setAssignForm({ ...assignForm, assignee_phone: e.target.value })} /></label>
              <label>Employee ID<input value={assignForm.assignee_emp_id} onChange={(e) => setAssignForm({ ...assignForm, assignee_emp_id: e.target.value })} /></label>
              <label>Expected Return<input type="date" value={assignForm.expected_return} onChange={(e) => setAssignForm({ ...assignForm, expected_return: e.target.value })} /></label>
              <label>Department<select value={assignForm.department} onChange={(e) => setAssignForm({ ...assignForm, department: e.target.value })}>{masters.departments.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</select></label>
              <label>Location<select value={assignForm.location} onChange={(e) => setAssignForm({ ...assignForm, location: e.target.value })}>{masters.locations.map((x) => <option key={x.id} value={x.name}>{x.name}</option>)}</select></label>
              <label className="s-span-all">Remarks<input value={assignForm.remarks} onChange={(e) => setAssignForm({ ...assignForm, remarks: e.target.value })} required /></label>
              <div className="s-form-actions s-span-all">
                <button className="s-btn-compact" type="submit">Assign Asset</button>
                <button type="button" className="s-ghost s-btn-compact" onClick={returnAsset}>Return to Inventory</button>
                <button type="button" className="s-warn s-btn-compact" onClick={markRepair}>Move to Repair</button>
              </div>
            </form>
            <div>
              <h3>Asset Table</h3>
              <table className="s-table">
                <thead><tr><th>Asset</th><th>Status</th><th>User</th></tr></thead>
                <tbody>
                  {assetRows.map((a) => (
                    <tr key={a.id}>
                      <td><button className="link-btn" onClick={() => openAsset(a.asset_id)}>{a.asset_id}</button></td>
                      <td>{a.status}</td>
                      <td>{a.assignee_name ? <button className="link-btn" onClick={() => openUser(a.assignee_name)}>{a.assignee_name}</button> : "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {view === "reports" && (
          <section className="s-panel">
            <p className="s-hint">Download business reports in CSV format for analysis and audit.</p>
            <div className="s-actions-inline">
              <button onClick={() => downloadReport("/reports/assets.csv", "assets_report.csv")}>Asset Register</button>
              <button onClick={() => downloadReport("/reports/current-assignments.csv", "current_assignments_report.csv")}>Current Assignments</button>
              <button onClick={() => downloadReport("/reports/assignment-history.csv", "assignment_history.csv")}>Assignment History</button>
              <button onClick={() => downloadReport("/reports/lifecycle-events.csv", "lifecycle_events_report.csv")}>Lifecycle Events</button>
              <button onClick={() => downloadReport("/reports/assets-by-status.csv", "assets_by_status_report.csv")}>Assets by Status</button>
              <button onClick={() => downloadReport("/reports/assets-by-department.csv", "assets_by_department_report.csv")}>Assets by Department</button>
            </div>
            <div className="s-panel-inset" style={{ marginTop: "12px" }}>
              <h3>Warranty Expiry</h3>
              <p className="s-muted">Choose a range and download assets with warranty ending in that period.</p>
              <div className="s-actions-inline">
                <input
                  type="number"
                  min="1"
                  max="3650"
                  value={reportDays}
                  onChange={(e) => setReportDays(Number(e.target.value || 60))}
                  style={{ maxWidth: "180px" }}
                />
                <button onClick={() => downloadReport(`/reports/warranty-expiry.csv?within_days=${reportDays}`, `warranty_expiry_${reportDays}d_report.csv`)}>
                  Download Warranty Expiry
                </button>
              </div>
            </div>
          </section>
        )}

        {view === "ids" && isAdmin && (
          <section className="s-panel s-grid2">
            <form className="s-form s-form-compact s-id-form" onSubmit={createId}>
              <label>Username<input value={idForm.username} onChange={(e) => setIdForm({ ...idForm, username: e.target.value })} required /></label>
              <label>Email<input value={idForm.email} onChange={(e) => setIdForm({ ...idForm, email: e.target.value })} required /></label>
              <label>Temporary Password<input type="password" value={idForm.password} onChange={(e) => setIdForm({ ...idForm, password: e.target.value })} required /></label>
              <label>Role<select value={idForm.role} onChange={(e) => setIdForm({ ...idForm, role: e.target.value })}><option>Admin</option><option>ITUser</option><option>Viewer</option></select></label>
              <button className="s-btn-compact s-span-all" type="submit">Create User</button>
            </form>
            <div className="s-panel-inset">
              <h3>Users</h3>
              <button className="s-ghost s-btn-compact" onClick={loadUsers}>Refresh</button>
              <div className="s-userlist">
                {users.map((u) => (
                  <div key={u.id} className="s-userrow">
                    <div><strong>{u.username}</strong> ({u.role})</div>
                    <div className="s-muted">{u.email} | {u.is_active ? "Active" : "Disabled"}</div>
                    <button className="s-danger s-btn-compact" onClick={() => deleteId(u.id)}>Deactivate</button>
                  </div>
                ))}
              </div>
              <div className="s-panel-inset" style={{ marginTop: "10px" }}>
                <h3>Branding</h3>
                <p className="s-muted">Upload customer/company logo (PNG/JPG/WEBP/GIF).</p>
                <form onSubmit={uploadLogo} className="s-actions-inline">
                  <input name="logo_file" type="file" accept=".png,.jpg,.jpeg,.webp,.gif" />
                  <button className="s-btn-compact" type="submit">Upload Logo</button>
                </form>
              </div>
            </div>
          </section>
        )}
      </section>

      {toast.open && <Toast toast={toast} onClose={() => setToast((t) => ({ ...t, open: false }))} />}
    </main>
  );
}

function Toast({ toast, onClose }) {
  return (
    <div className={`s-toast ${toast.type}`}>
      <div>{toast.message}</div>
      <button onClick={onClose}>x</button>
    </div>
  );
}

function todayISO() { return new Date().toISOString().slice(0, 10); }
function addDaysISO(days) { const d = new Date(); d.setDate(d.getDate() + days); return d.toISOString().slice(0, 10); }

function parseApiTimestamp(value) {
  if (!value) return null;
  if (value instanceof Date) return value;
  if (typeof value !== "string") return new Date(value);

  let s = value.trim();
  if (!s) return null;

  // Normalize "YYYY-MM-DD HH:mm:ss(.ffffff)" -> ISO-like
  s = s.replace(" ", "T");

  const hasZone = /(?:Z|[+\-]\d{2}:\d{2})$/.test(s);
  if (!hasZone) {
    // Backend stores naive UTC; make it explicit for deterministic parsing.
    s = `${s}Z`;
  }

  // JS Date supports milliseconds; trim higher precision fractional seconds.
  s = s.replace(/\.(\d{3})\d+(?=Z|[+\-]\d{2}:\d{2}$)/, ".$1");

  return new Date(s);
}

function formatIST(value) {
  if (!value) return "-";
  const d = parseApiTimestamp(value);
  if (!d || Number.isNaN(d.getTime())) return String(value);
  return new Intl.DateTimeFormat("en-IN", {
    timeZone: "Asia/Kolkata",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(d);
}

async function safeDetail(res) {
  try {
    const json = await res.json();
    const detail = json?.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail.map((d) => `${Array.isArray(d?.loc) ? d.loc.join(".") : "field"}: ${d?.msg || JSON.stringify(d)}`).join("; ");
    }
    if (detail && typeof detail === "object") return JSON.stringify(detail);
    return JSON.stringify(json);
  } catch {
    return `${res.status} ${res.statusText}`;
  }
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
