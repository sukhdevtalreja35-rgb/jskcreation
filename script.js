window.firebaseReady = (async function () {
  try {
    var appMod =
      await import("https://www.gstatic.com/firebasejs/10.13.0/firebase-app.js");
    var fsMod =
      await import("https://www.gstatic.com/firebasejs/10.13.0/firebase-firestore.js");
    var firebaseConfig = {
      apiKey: "AIzaSyAP1W9aEd6alEs-3Ac2s36ecRT6sIkzkFs",
      authDomain: "jsk-creation.firebaseapp.com",
      projectId: "jsk-creation",
      storageBucket: "jsk-creation.firebasestorage.app",
      messagingSenderId: "682729907422",
      appId: "1:682729907422:web:7a2b9a127ef70a4e0e8e4f",
      measurementId: "G-1QGH1N1EMR",
    };
    var app = appMod.initializeApp(firebaseConfig);
    var db = fsMod.getFirestore(app);
    return {
      db: db,
      doc: fsMod.doc,
      getDoc: fsMod.getDoc,
      setDoc: fsMod.setDoc,
      collection: fsMod.collection,
      query: fsMod.query,
      orderBy: fsMod.orderBy,
      onSnapshot: fsMod.onSnapshot,
      updateDoc: fsMod.updateDoc,
      ok: true,
    };
  } catch (e) {
    console.error(
      "Firebase init failed, falling back to local storage only.",
      e,
    );
    return { ok: false };
  }
})();

(function () {
  "use strict";

  /* ================= persistence layer =================
     Order of preference: window.storage (claude.ai artifact
     sandbox) -> Firebase Firestore (cross-device cloud sync)
     -> localStorage (offline cache / standalone fallback)
     -> in-memory object (last resort, e.g. private/blocked storage) */
  var memoryFallback = {};
  var LS_PREFIX = "jsk-creation:";
  var FIRESTORE_COLLECTION = "jsk-creation";

  function lsGet(key) {
    try {
      var raw = window.localStorage.getItem(LS_PREFIX + key);
      return raw == null ? undefined : JSON.parse(raw);
    } catch (e) {
      return undefined;
    }
  }
  function lsSet(key, value) {
    try {
      window.localStorage.setItem(LS_PREFIX + key, JSON.stringify(value));
      return true;
    } catch (e) {
      return false;
    }
  }

  async function storeGet(key, fallback) {
    try {
      if (window.storage) {
        var res = await window.storage.get(key, false);
        if (res) return JSON.parse(res.value);
      }
    } catch (e) {
      /* key not found in window.storage, keep looking */
    }
    try {
      var fb = await window.firebaseReady;
      if (fb && fb.ok) {
        var ref = fb.doc(fb.db, FIRESTORE_COLLECTION, key);
        var snap = await fb.getDoc(ref);
        if (snap.exists()) {
          var val = snap.data().value;
          lsSet(key, val); // keep a local cache too
          return val;
        }
      }
    } catch (e) {
      console.warn("Firestore read failed for", key, e);
    }
    var ls = lsGet(key);
    if (ls !== undefined) return ls;
    return memoryFallback.hasOwnProperty(key) ? memoryFallback[key] : fallback;
  }
  async function storeSet(key, value) {
    memoryFallback[key] = value;
    lsSet(key, value);
    try {
      if (window.storage) {
        await window.storage.set(key, JSON.stringify(value), false);
      }
    } catch (e) {
      /* localStorage already has it as a safety net */
    }
    try {
      var fb = await window.firebaseReady;
      if (fb && fb.ok) {
        var ref = fb.doc(fb.db, FIRESTORE_COLLECTION, key);
        await fb.setDoc(ref, { value: value });
      }
    } catch (e) {
      console.warn("Firestore write failed for", key, e);
    }
  }

  /* ================= warehouse login gate =================
     Password itself is never stored in the code. Only its SHA-256
     hash is saved (in Firestore/localStorage via storeGet/storeSet),
     and it's chosen by whoever sets it up on first visit. This blocks
     casual access to the dashboard; it is not bank-grade security
     since everything here runs in the browser. */
  var AUTH_KEY = "warehouseAuth";
  var AUTH_LOCAL_FLAG = LS_PREFIX + "warehouseAuthed";
  var WAREHOUSE_USERNAME = "jskcreation";
  var gate = { mode: "login", error: "", busy: false };

  function isAuthedOnThisDevice() {
    try {
      return window.localStorage.getItem(AUTH_LOCAL_FLAG) === "1";
    } catch (e) {
      return false;
    }
  }
  function setAuthedOnThisDevice(flag) {
    try {
      if (flag) window.localStorage.setItem(AUTH_LOCAL_FLAG, "1");
      else window.localStorage.removeItem(AUTH_LOCAL_FLAG);
    } catch (e) {
      /* ignore */
    }
  }
  /* Plain-JS fallback hash (FNV-1a based, stretched) used only when
     crypto.subtle is unavailable — e.g. the site is being served over
     plain HTTP instead of HTTPS, where browsers disable the Web Crypto
     API. Without this fallback, login/setup would silently hang forever
     since crypto.subtle.digest() would throw on an undefined object. */
  function fallbackHashHex(text) {
    var str = "jsk-salt-" + text;
    var h1 = 0x811c9dc5,
      h2 = 0x811c9dc5;
    for (var round = 0; round < 5000; round++) {
      for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
        h1 ^= c;
        h1 = (h1 * 16777619) >>> 0;
        h2 ^= c + round;
        h2 = (h2 * 2166136261) >>> 0;
      }
      str = h1.toString(16) + h2.toString(16);
    }
    return (h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0"));
  }

  async function sha256Hex(text) {
    try {
      if (!window.crypto || !window.crypto.subtle) {
        throw new Error("crypto.subtle unavailable (page not on HTTPS)");
      }
      var data = new TextEncoder().encode(text);
      var hashBuf = await crypto.subtle.digest("SHA-256", data);
      var bytes = Array.from(new Uint8Array(hashBuf));
      return bytes
        .map(function (b) {
          return b.toString(16).padStart(2, "0");
        })
        .join("");
    } catch (e) {
      console.warn(
        "sha256 via crypto.subtle failed, using fallback hash. " +
          "This usually means the page isn't served over HTTPS.",
        e,
      );
      return "fb:" + fallbackHashHex(text);
    }
  }

  function renderGate() {
    var isSetup = gate.mode === "setup";
    var title = isSetup ? "Set Up Warehouse Password" : "Warehouse Login";
    var sub = isSetup
      ? "One-time setup — choose a password to protect this dashboard. Only people who know it will be able to log in."
      : "Enter your username and password to continue.";
    var fields = isSetup
      ? '<div class="field"><label>Username</label><input type="text" value="' +
        esc(WAREHOUSE_USERNAME) +
        '" readonly></div>' +
        '<div class="field"><label>Choose Password</label><input type="password" id="gatePass" autocomplete="new-password" required minlength="4"></div>' +
        '<div class="field"><label>Confirm Password</label><input type="password" id="gateConfirmPass" autocomplete="new-password" required minlength="4"></div>'
      : '<div class="field"><label>Username</label><input type="text" id="gateUser" autocomplete="username" required></div>' +
        '<div class="field"><label>Password</label><input type="password" id="gatePass" autocomplete="current-password" required></div>';

    return (
      '<div class="gate-wrap">' +
      '<form id="gate-form" class="gate-card">' +
      '<div style="display:flex;align-items:center;gap:10px;"><img src="logo-mark.png" alt="JSK Creation" class="brand-mark"><small style="color:var(--gold-soft);background:var(--maroon);display:inline-block;padding:2px 8px;border-radius:4px;">Warehouse Access</small></div>' +
      '<h2 class="display" style="margin:18px 0 4px;">' +
      title +
      "</h2>" +
      '<p class="muted" style="margin:0 0 18px;">' +
      sub +
      "</p>" +
      fields +
      (gate.error
        ? '<p class="gate-error">' + esc(gate.error) + "</p>"
        : "") +
      '<button type="submit" class="btn btn-primary" id="gateSubmitBtn" style="width:100%;justify-content:center;margin-top:6px;">' +
      (isSetup ? "Set Password &amp; Continue" : "Login") +
      "</button>" +
      '<a href="index.html" class="back-to-store" style="display:block;text-align:center;margin-top:16px;position:static;">&larr; Back to Store</a>' +
      "</form>" +
      "</div>"
    );
  }

  function showGate() {
    document.getElementById("app").innerHTML = renderGate();
    bindGateEvents();
  }

  function bindGateEvents() {
    var form = document.getElementById("gate-form");
    if (!form) return;
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      if (gate.busy) return;
      if (gate.mode === "setup") handleSetupSubmit();
      else handleLoginSubmit();
    });
  }

  async function handleSetupSubmit() {
    var pass = document.getElementById("gatePass").value;
    var confirm = document.getElementById("gateConfirmPass").value;
    if (!pass || pass.length < 4) {
      gate.error = "Password kam se kam 4 characters ka hona chahiye.";
      showGate();
      return;
    }
    if (pass !== confirm) {
      gate.error = "Dono password match nahi ho rahe.";
      showGate();
      return;
    }
    gate.busy = true;
    try {
      var hash = await sha256Hex(pass);
      await storeSet(AUTH_KEY, { passwordHash: hash });
      setAuthedOnThisDevice(true);
      gate.busy = false;
      init();
    } catch (e) {
      console.error("Setup failed:", e);
      gate.busy = false;
      gate.error = "Kuch ghalat ho gaya, dobara koshish karein.";
      showGate();
    }
  }

  async function handleLoginSubmit() {
    var user = document.getElementById("gateUser").value.trim().toLowerCase();
    var pass = document.getElementById("gatePass").value;
    gate.busy = true;
    try {
      /* kick off the app-data fetch at the same time as the password
         check, instead of waiting for login to finish first — the two
         network round-trips happen together instead of back-to-back */
      var dataPromise = fetchAppData();
      var auth = await storeGet(AUTH_KEY, null);
      var hash = await sha256Hex(pass || "");
      gate.busy = false;
      if (
        !auth ||
        user !== WAREHOUSE_USERNAME ||
        hash !== auth.passwordHash
      ) {
        gate.error = "Galat username ya password.";
        showGate();
        return;
      }
      gate.error = "";
      setAuthedOnThisDevice(true);
      init(dataPromise);
    } catch (e) {
      console.error("Login failed:", e);
      gate.busy = false;
      gate.error = "Kuch ghalat ho gaya, dobara koshish karein.";
      showGate();
    }
  }

  async function boot() {
    var auth = await storeGet(AUTH_KEY, null);
    if (!auth || !auth.passwordHash) {
      gate.mode = "setup";
      showGate();
      return;
    }
    /* Always ask for the password on every fresh visit to the warehouse
       page (including coming back via "Back to Store"), even if this
       device logged in successfully before. */
    gate.mode = "login";
    showGate();
  }

  async function submitChangePassword() {
    var current = document.getElementById("cpCurrent").value;
    var next = document.getElementById("cpNew").value;
    var confirm = document.getElementById("cpConfirm").value;
    var auth = await storeGet(AUTH_KEY, null);
    var currentHash = await sha256Hex(current || "");
    if (!auth || currentHash !== auth.passwordHash) {
      state.modal = {
        type: "changePassword",
        payload: { error: "Current password galat hai." },
      };
      render();
      return;
    }
    if (!next || next.length < 4) {
      state.modal = {
        type: "changePassword",
        payload: { error: "New password kam se kam 4 characters ka ho." },
      };
      render();
      return;
    }
    if (next !== confirm) {
      state.modal = {
        type: "changePassword",
        payload: { error: "Naye password match nahi ho rahe." },
      };
      render();
      return;
    }
    var newHash = await sha256Hex(next);
    await storeSet(AUTH_KEY, { passwordHash: newHash });
    state.modal = null;
    render();
  }

  function logout() {
    setAuthedOnThisDevice(false);
    gate.mode = "login";
    gate.error = "";
    showGate();
  }

  /* ================= state ================= */
  var state = {
    view: "dashboard",
    items: [],
    invoices: [],
    orders: [],
    ordersSubscribed: false,
    invoiceCounter: 1000,
    modal: null,
    draft: null,
    activeInvoiceId: null,
    activeItemId: null,
    clientFilter: null,
    monthFilter: null,
    rangeFilter: null,
    formErrors: null,
    editingInvoiceId: null,
    editingSnapshot: null,
    activeComboLine: null,
    pendingLineForNewItem: null,
    itemSearchQuery: "",
    clientSearchQuery: "",
    bulkDraft: null,
    editingBatchId: null,
    editingBatchSnapshot: null,
    activeBatchId: null,
    earningsRangeFrom: "",
    earningsRangeTo: "",
  };

  var PALETTE = [
    "#6C1E3C",
    "#0F6E6E",
    "#C9973B",
    "#3E5C76",
    "#7A4A9E",
    "#1F6E43",
    "#A23B2E",
    "#2E4A6B",
  ];
  function colorFor(name) {
    var str = name || "?";
    var hash = 0;
    for (var i = 0; i < str.length; i++) {
      hash = (hash * 31 + str.charCodeAt(i)) >>> 0;
    }
    return PALETTE[hash % PALETTE.length];
  }
  function initials(name) {
    var parts = (name || "?").trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) return "?";
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }

  var UNIT_LABELS = {
    pc: "pc",
    pair: "pair",
    packet: "packet",
    yard: "yard",
    gram: "gram",
  };
  function unitLabel(unit) {
    return UNIT_LABELS[unit] || "pc";
  }
  var CATEGORY_LABELS = {
    tulip: "Tulip",
    moon: "Moon",
    lotus: "Lotus",
    kundan: "Kundan",
    "ghanthan-mala": "Ghanthan Mala",
    connectors: "Connectors",
    minakari: "Minakari",
    chains: "Chains",
    stones: "Stones",
  };
  function categoryLabel(cat) {
    var found =
      state.categories &&
      state.categories.find(function (c) {
        return c.id === cat;
      });
    if (found) return found.label;
    return CATEGORY_LABELS[cat] || "Tulip";
  }
  function slugify(str) {
    var base = String(str || "")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
    return base || "category";
  }
  function fmtMoney(n) {
    n = Number(n) || 0;
    return "Rs. " + n.toLocaleString("en-US", { maximumFractionDigits: 2 });
  }
  function fmtDate(iso) {
    if (!iso) return "";
    var d = new Date(iso + "T00:00:00");
    return d.toLocaleDateString("en-IN", {
      day: "2-digit",
      month: "short",
      year: "numeric",
    });
  }
  function uid() {
    return (
      "id" + Date.now().toString(36) + Math.random().toString(36).slice(2, 7)
    );
  }

  /* filters items for the item combobox: matches whose NAME or any WORD in the
     name starts with the query are ranked first, plain substring matches after */
  function comboFilter(items, query) {
    var q = (query || "").trim().toLowerCase();
    if (!q) return items;
    var starts = [],
      contains = [];
    items.forEach(function (i) {
      var nameLower = i.name.toLowerCase();
      var words = nameLower.split(/\s+/);
      if (
        words.some(function (w) {
          return w.indexOf(q) === 0;
        })
      ) {
        starts.push(i);
      } else if (nameLower.indexOf(q) > -1) {
        contains.push(i);
      }
    });
    return starts.concat(contains);
  }

  /* re-renders the whole app while keeping the currently focused search/combo
     input focused (and its cursor position), since render() replaces all HTML */
  function withPreservedFocus(renderFn) {
    var active = document.activeElement;
    var selector = null,
      selStart = null,
      selEnd = null;
    var trackAttrs = ["data-combo-input", "data-item-search", "data-client-search"];
    if (active) {
      for (var i = 0; i < trackAttrs.length; i++) {
        if (active.hasAttribute(trackAttrs[i])) {
          var val = active.getAttribute(trackAttrs[i]);
          selector = val
            ? "[" + trackAttrs[i] + '="' + val.replace(/"/g, '\\"') + '"]'
            : "[" + trackAttrs[i] + "]";
          break;
        }
      }
      try {
        selStart = active.selectionStart;
        selEnd = active.selectionEnd;
      } catch (e) {}
    }
    renderFn();
    if (selector) {
      var el = document.querySelector(selector);
      if (el) {
        el.focus();
        if (selStart != null) {
          try {
            el.setSelectionRange(selStart, selEnd);
          } catch (e) {}
        }
      }
    }
  }

  /* thumbnail markup for an item/line: real picture if provided, else a monogram badge */
  function thumbHTML(entity, size) {
    size = size || 36;
    var style = "width:" + size + "px;height:" + size + "px;";
    if (entity.img) {
      return (
        '<div class="thumb" style="' +
        style +
        '"><img src="' +
        esc(entity.img) +
        '" alt="" onerror="this.parentElement.innerHTML=\'' +
        initials(entity.name) +
        "';this.parentElement.style.background='" +
        colorFor(entity.name) +
        "';\"></div>"
      );
    }
    var bg = entity.color || colorFor(entity.name);
    return (
      '<div class="thumb" style="' +
      style +
      ";background:" +
      bg +
      ';">' +
      initials(entity.name) +
      "</div>"
    );
  }

  /* Resize + compress a picked image file to a JPEG data URL so it can
     sync through Firestore without blowing the document size limit. */
  function compressImageFile(file, maxSide, quality) {
    maxSide = maxSide || 800;
    quality = quality == null ? 0.72 : quality;
    return new Promise(function (resolve, reject) {
      if (!file || !/^image\//.test(file.type || "")) {
        reject(new Error("Please choose an image file (JPG, PNG, or WebP)."));
        return;
      }
      if (file.size > 12 * 1024 * 1024) {
        reject(new Error("Image is too large. Please use a file under 12 MB."));
        return;
      }
      var reader = new FileReader();
      reader.onerror = function () {
        reject(new Error("Could not read that file."));
      };
      reader.onload = function () {
        var img = new Image();
        img.onerror = function () {
          reject(new Error("Could not open that image."));
        };
        img.onload = function () {
          var w = img.naturalWidth || img.width;
          var h = img.naturalHeight || img.height;
          var scale = Math.min(1, maxSide / Math.max(w, h));
          w = Math.max(1, Math.round(w * scale));
          h = Math.max(1, Math.round(h * scale));
          var canvas = document.createElement("canvas");
          canvas.width = w;
          canvas.height = h;
          var ctx = canvas.getContext("2d");
          ctx.fillStyle = "#ffffff";
          ctx.fillRect(0, 0, w, h);
          ctx.drawImage(img, 0, 0, w, h);
          try {
            resolve(canvas.toDataURL("image/jpeg", quality));
          } catch (e) {
            reject(new Error("Could not process that image."));
          }
        };
        img.src = reader.result;
      };
      reader.readAsDataURL(file);
    });
  }

  function optionRowsHtml(rows, prefix, placeholder) {
    rows = rows && rows.length ? rows : [];
    return rows
      .map(function (o) {
        return (
          '<div class="opt-row" data-opt-row>' +
          '<input type="text" name="' + prefix + 'Label[]" value="' +
          esc(o.label || "") +
          '" placeholder="' + esc(placeholder || "Label") + '" class="opt-label-input">' +
          '<div class="prefix-input opt-price-input"><span class="prefix-tag">Rs.</span><input type="number" min="0" step="1" name="' +
          prefix + 'Price[]" value="' +
          (o.price != null && o.price !== "" ? o.price : "") +
          '" placeholder="Price"></div>' +
          '<button type="button" class="btn btn-ghost opt-row-remove" data-remove-opt-row aria-label="Remove">&times;</button>' +
          "</div>"
        );
      })
      .join("");
  }
  function colorRowsHtml(rows) {
    rows = rows && rows.length ? rows : [];
    return rows
      .map(function (c) {
        return (
          '<div class="opt-row" data-opt-row>' +
          '<input type="text" name="colorName[]" value="' +
          esc(c.name || "") +
          '" placeholder="e.g. Red" class="opt-label-input">' +
          '<input type="color" name="colorHex[]" value="' +
          esc(c.hex || "#B8842E") +
          '" class="opt-color-input">' +
          '<button type="button" class="btn btn-ghost opt-row-remove" data-remove-opt-row aria-label="Remove">&times;</button>' +
          "</div>"
        );
      })
      .join("");
  }

  function setImgPreview(n, src) {
    var preview = document.getElementById("imgPreview" + n);
    var hidden = document.getElementById("imgHidden" + n);
    var clearBtn = document.getElementById("imgClearBtn" + n);
    var browseBtn = document.querySelector(
      'label.img-browse-btn[for="imgFileInput' + n + '"]',
    );
    if (hidden) hidden.value = src || "";
    if (clearBtn) clearBtn.hidden = !src;
    if (browseBtn) browseBtn.textContent = src ? "Change" : "Browse";
    if (!preview) return;
    if (src) {
      preview.innerHTML = '<img src="' + esc(src) + '" alt="Preview ' + n + '">';
      preview.classList.add("has-img");
    } else {
      preview.innerHTML =
        '<span class="img-upload-placeholder">Photo ' + n + "</span>";
      preview.classList.remove("has-img");
    }
  }

  /* ================= init ================= */
  var DEFAULT_CATEGORIES = [
    { id: "tulip", label: "Tulip", parentId: null },
    { id: "moon", label: "Moon", parentId: null },
    { id: "lotus", label: "Lotus", parentId: null },
    { id: "kundan", label: "Kundan", parentId: null },
    { id: "ghanthan-mala", label: "Ghanthan Mala", parentId: null },
    { id: "connectors", label: "Connectors", parentId: null },
    { id: "minakari", label: "Minakari", parentId: null },
    { id: "chains", label: "Chains", parentId: null },
    { id: "stones", label: "Stones", parentId: null },
  ];
  async function fetchAppData() {
    var results = await Promise.all([
      storeGet("items", null),
      storeGet("invoices", []),
      storeGet("invoiceCounter", 1000),
      storeGet("categories", null),
    ]);
    var items = results[0];
    var invoices = results[1];
    var counter = results[2];
    var categories = results[3];
    if (!items) {
      items = [
        {
          id: uid(),
          name: "Kundan",
          img: "",
          color: colorFor("Kundan"),
          qty: 12,
          price: 100,
          unit: "pc",
          cat: "kundan",
          desc: "",
          sku: "",
          unitLabel: "",
        },
        {
          id: uid(),
          name: "Chain",
          img: "",
          color: colorFor("Chain"),
          qty: 34,
          price: 100,
          unit: "pc",
          cat: "chains",
          desc: "",
          sku: "",
          unitLabel: "",
        },
        {
          id: uid(),
          name: "Beads",
          img: "",
          color: colorFor("Beads"),
          qty: 56,
          price: 100,
          unit: "packet",
          cat: "tulip",
          desc: "",
          sku: "",
          unitLabel: "",
        },
      ];
      storeSet("items", items);
    }
    if (!categories || !categories.length) {
      categories = DEFAULT_CATEGORIES.slice();
      storeSet("categories", categories);
    }
    return { items: items, invoices: invoices, counter: counter, categories: categories };
  }

  async function init(dataPromise) {
    var data = await (dataPromise || fetchAppData());
    state.items = data.items;
    state.invoices = data.invoices;
    state.invoiceCounter = data.counter;
    state.categories = data.categories;
    render();
    subscribeOrders();
  }

  /* ================= incoming orders (from the website) =================
     Customers placing an order on index.html write a document straight
     into the "orders" Firestore collection. We listen live here so a new
     order shows up on this dashboard (and its badge count) the instant
     it comes in, with no refresh needed. Nothing is billed and no stock
     is touched until a staff member reviews it and clicks "Bill Banayen". */
  async function subscribeOrders() {
    if (state.ordersSubscribed) return;
    try {
      var fb = await window.firebaseReady;
      if (!fb || !fb.ok) {
        console.warn(
          "Orders sync skipped: Firebase did not initialise (offline or blocked).",
        );
        return;
      }
      state.ordersSubscribed = true;
      // no server-side orderBy here on purpose — if a doc from the website
      // is ever missing/mistyped createdAt, Firestore silently excludes it
      // from an orderBy query, which looks exactly like "orders aren't
      // coming in". Sorting client-side after the fact avoids that trap.
      fb.onSnapshot(
        fb.collection(fb.db, "orders"),
        function (snap) {
          state.orders = snap.docs
            .map(function (d) {
              var data = d.data();
              data.id = d.id;
              return data;
            })
            .sort(function (a, b) {
              var ta = a.createdAt ? new Date(a.createdAt).getTime() : 0;
              var tb = b.createdAt ? new Date(b.createdAt).getTime() : 0;
              return tb - ta;
            });
          render();
        },
        function (err) {
          console.error(
            "Orders live sync failed — this is almost always a Firestore " +
              "Security Rules problem (the 'orders' collection needs to " +
              "allow read/list, not just create, or the Warehouse can " +
              "never see what customers submit):",
            err && err.code,
            err,
          );
        },
      );
    } catch (e) {
      console.error("Could not subscribe to orders:", e);
    }
  }

  function pendingOrders() {
    return state.orders.filter(function (o) {
      return o.status === "pending";
    });
  }

  async function setOrderStatus(orderId, status, extra) {
    var order = state.orders.find(function (o) {
      return o.id === orderId;
    });
    if (order) order.status = status;
    try {
      var fb = await window.firebaseReady;
      if (fb && fb.ok) {
        var ref = fb.doc(fb.db, "orders", orderId);
        await fb.updateDoc(
          ref,
          Object.assign({ status: status }, extra || {}),
        );
      }
    } catch (e) {
      console.warn("Could not update order status:", e);
    }
  }

  function dismissOrder(orderId) {
    setOrderStatus(orderId, "dismissed");
    render();
  }

  function billOrder(orderId) {
    var order = state.orders.find(function (o) {
      return o.id === orderId;
    });
    if (!order) return;
    state.invoiceCounter += 1;
    var cust = order.customer || {};
    var addressBits = [cust.address, cust.city].filter(Boolean).join(", ");
    state.draft = {
      invoiceNo: "JSK-" + state.invoiceCounter,
      deliveryCharges: 0,
      date: new Date().toISOString().slice(0, 10),
      clientName: cust.name || "",
      phone: cust.phone || "",
      address: addressBits,
      lines: (order.lines || []).map(function (l) {
        return {
          id: uid(),
          itemId: l.itemId,
          qty: l.qty,
          query: l.name || "",
          // keep the pack price the customer actually saw/selected on the
          // website, so billing this order doesn't fall back to the item's
          // single-piece price when it was really a multi-piece pack.
          price: typeof l.price === "number" ? l.price : undefined,
          variant: l.variant || "",
        };
      }),
      sourceOrderId: order.id,
    };
    state.editingInvoiceId = null;
    state.editingSnapshot = null;
    state.view = "new-invoice";
    render();
  }

  async function saveItems() {
    await storeSet("items", state.items);
  }
  async function saveCategories() {
    await storeSet("categories", state.categories);
  }
  async function saveInvoices() {
    await storeSet("invoices", state.invoices);
  }
  async function saveCounter() {
    await storeSet("invoiceCounter", state.invoiceCounter);
  }

  /* ================= navigation ================= */
  function abandonEditIfAny() {
    if (state.editingInvoiceId && state.editingSnapshot) {
      state.editingSnapshot.forEach(function (l) {
        var item = state.items.find(function (i) {
          return i.id === l.itemId;
        });
        if (item) item.qty = Math.max(0, item.qty - l.qty);
      });
      saveItems();
    }
    state.editingInvoiceId = null;
    state.editingSnapshot = null;
  }

  function goTo(view) {
    if (
      state.view === "new-invoice" &&
      view !== "new-invoice" &&
      state.editingInvoiceId
    ) {
      abandonEditIfAny();
      state.draft = null;
      state.formErrors = null;
    }
    state.view = view;
    if (view === "new-invoice" && !state.draft) {
      startDraft();
    }
    if (view !== "invoices") {
      state.clientFilter = null;
      state.monthFilter = null;
      state.rangeFilter = null;
    }
    render();
  }

  function startDraft() {
    state.invoiceCounter += 1;
    state.draft = {
      invoiceNo: "JSK-" + state.invoiceCounter,
      deliveryCharges: 0,
      date: new Date().toISOString().slice(0, 10),
      clientName: "",
      phone: "",
      address: "",
      lines: [{ id: uid(), itemId: "", qty: 1, query: "" }],
    };
  }

  function startDraftForItem(itemId) {
    state.invoiceCounter += 1;
    state.draft = {
      invoiceNo: "JSK-" + state.invoiceCounter,
      deliveryCharges: 0,
      date: new Date().toISOString().slice(0, 10),
      clientName: "",
      phone: "",
      address: "",
      lines: [{ id: uid(), itemId: itemId, qty: 1, query: "" }],
    };
    state.editingInvoiceId = null;
    state.editingSnapshot = null;
    state.view = "new-invoice";
    render();
  }

  /* ================= bulk (one item, many clients) invoice ================= */
  function startBulkInvoice(itemId) {
    state.bulkDraft = {
      itemId: itemId || "",
      date: new Date().toISOString().slice(0, 10),
      rows: [{ id: uid(), name: "", qty: 1 }],
    };
    state.editingBatchId = null;
    state.editingBatchSnapshot = null;
    state.formErrors = null;
    state.view = "bulk-invoice";
    render();
  }

  /* reopen a previously saved multi-client order for editing. All the
     invoices that make up this batch get their stock returned first
     (same idea as editInvoice) so quantities can be freely adjusted;
     if the edit is cancelled, editingBatchSnapshot is used to put that
     stock straight back. */
  function editBulkBatch(batchId) {
    var invs = state.invoices.filter(function (i) {
      return i.batchId === batchId;
    });
    if (!invs.length) return;
    var snapshot = [];
    invs.forEach(function (inv) {
      inv.lines.forEach(function (l) {
        var item = state.items.find(function (i) {
          return i.id === l.itemId;
        });
        if (item) item.qty += l.qty;
        snapshot.push({ itemId: l.itemId, qty: l.qty });
      });
    });
    saveItems();
    var firstLine = invs[0].lines[0];
    state.bulkDraft = {
      itemId: firstLine.itemId,
      date: invs[0].date,
      rows: invs.map(function (inv) {
        return {
          id: inv.id,
          name: inv.clientName,
          qty: inv.lines[0].qty,
          _existing: true,
        };
      }),
    };
    state.editingBatchId = batchId;
    state.editingBatchSnapshot = snapshot;
    state.formErrors = null;
    state.view = "bulk-invoice";
    render();
  }

  /* groups saved invoices that share a batchId back into one
     "multi-client order" so it can be viewed/edited as a whole again. */
  function getBulkBatches() {
    var map = {};
    var order = [];
    state.invoices.forEach(function (inv) {
      if (!inv.batchId) return;
      if (!map[inv.batchId]) {
        map[inv.batchId] = [];
        order.push(inv.batchId);
      }
      map[inv.batchId].push(inv);
    });
    return order
      .map(function (bid) {
        var invs = map[bid];
        var first = invs[0];
        var line0 = first.lines[0];
        var item = state.items.find(function (i) {
          return i.id === line0.itemId;
        });
        var totalQty = invs.reduce(function (s, inv) {
          return s + (inv.lines[0] ? inv.lines[0].qty : 0);
        }, 0);
        var totalAmount = invs.reduce(function (s, inv) {
          return s + inv.total;
        }, 0);
        return {
          id: bid,
          date: first.date,
          itemId: line0.itemId,
          itemName: item ? item.name : line0.name || "Deleted item",
          clients: invs.length,
          totalQty: totalQty,
          totalAmount: totalAmount,
          invoices: invs,
        };
      })
      .sort(function (a, b) {
        return (b.date || "").localeCompare(a.date || "");
      });
  }

  function viewBulkBatch(batchId) {
    state.activeBatchId = batchId;
    state.view = "bulk-order-view";
    render();
  }

  function confirmDeleteBulkBatch(batchId) {
    state.modal = { type: "confirmDeleteBulkBatch", payload: { id: batchId } };
    render();
  }

  async function deleteBulkBatch(batchId) {
    var invs = state.invoices.filter(function (i) {
      return i.batchId === batchId;
    });
    invs.forEach(function (inv) {
      inv.lines.forEach(function (l) {
        var item = state.items.find(function (i) {
          return i.id === l.itemId;
        });
        if (item) item.qty += l.qty;
      });
    });
    saveItems();
    state.invoices = state.invoices.filter(function (i) {
      return i.batchId !== batchId;
    });
    saveInvoices();
    state.modal = null;
    if (state.activeBatchId === batchId) state.activeBatchId = null;
    state.view = "bulk-orders";
    render();
  }
  function bulkItem() {
    if (!state.bulkDraft) return null;
    return state.items.find(function (i) {
      return i.id === state.bulkDraft.itemId;
    });
  }
  function updateBulkItem(itemId) {
    state.bulkDraft.itemId = itemId;
    render();
  }
  function addBulkRow() {
    state.bulkDraft.rows.push({ id: uid(), name: "", qty: 1 });
    render();
  }
  function removeBulkRow(rowId) {
    if (state.bulkDraft.rows.length === 1) return;
    state.bulkDraft.rows = state.bulkDraft.rows.filter(function (r) {
      return r.id !== rowId;
    });
    render();
  }
  function updateBulkRow(rowId, field, value) {
    var row = state.bulkDraft.rows.find(function (r) {
      return r.id === rowId;
    });
    if (!row) return;
    if (field === "qty") row.qty = Math.max(0, Number(value) || 0);
    else row.name = value;
  }
  function bulkRowAmount(row) {
    var item = bulkItem();
    return item ? item.price * (Number(row.qty) || 0) : 0;
  }
  function bulkGrandQty() {
    return state.bulkDraft.rows.reduce(function (s, r) {
      return s + (Number(r.qty) || 0);
    }, 0);
  }
  function bulkGrandTotal() {
    var item = bulkItem();
    if (!item) return 0;
    return state.bulkDraft.rows.reduce(function (s, r) {
      return s + item.price * (Number(r.qty) || 0);
    }, 0);
  }
  function bulkErrors() {
    var errs = [];
    var item = bulkItem();
    if (!item) {
      errs.push("Select an item first.");
      return errs;
    }
    var validRows = state.bulkDraft.rows.filter(function (r) {
      return r.name.trim() && Number(r.qty) > 0;
    });
    if (validRows.length === 0) {
      errs.push("Add at least one client with a name and quantity.");
    }
    var totalQty = validRows.reduce(function (s, r) {
      return s + Number(r.qty);
    }, 0);
    if (totalQty > item.qty) {
      errs.push(
        "Only " +
          item.qty +
          " " +
          unitLabel(item.unit) +
          " of " +
          item.name +
          " in stock — this order needs " +
          totalQty +
          ".",
      );
    }
    return errs;
  }
  async function saveBulkInvoice() {
    var errs = bulkErrors();
    if (errs.length) {
      state.formErrors = errs;
      render();
      return;
    }
    var item = bulkItem();
    var validRows = state.bulkDraft.rows.filter(function (r) {
      return r.name.trim() && Number(r.qty) > 0;
    });
    var date = state.bulkDraft.date;
    var isEdit = !!state.editingBatchId;
    var batchId = isEdit ? state.editingBatchId : uid();

    if (isEdit) {
      // any existing rows the user removed while editing need their
      // invoice deleted outright (their stock was already returned
      // when the batch was opened for editing)
      var keptIds = validRows
        .filter(function (r) {
          return r._existing;
        })
        .map(function (r) {
          return r.id;
        });
      state.invoices = state.invoices.filter(function (inv) {
        if (inv.batchId !== batchId) return true;
        return keptIds.indexOf(inv.id) !== -1;
      });
    }

    validRows.forEach(function (r) {
      var qty = Number(r.qty);
      var amount = item.price * qty;
      if (r._existing) {
        var existing = state.invoices.find(function (i) {
          return i.id === r.id;
        });
        if (existing) {
          existing.date = date;
          existing.clientName = r.name.trim();
          existing.batchId = batchId;
          existing.lines = [
            {
              itemId: item.id,
              name: item.name,
              img: item.img,
              color: item.color,
              unit: item.unit,
              qty: qty,
              price: item.price,
              amount: amount,
            },
          ];
          existing.subtotal = amount;
          existing.total = amount;
        }
      } else {
        state.invoiceCounter += 1;
        var invoice = {
          id: uid(),
          invoiceNo: "JSK-" + state.invoiceCounter,
          batchId: batchId,
          deliveryCharges: 0,
          date: date,
          clientName: r.name.trim(),
          phone: "",
          address: "",
          lines: [
            {
              itemId: item.id,
              name: item.name,
              img: item.img,
              color: item.color,
              unit: item.unit,
              qty: qty,
              price: item.price,
              amount: amount,
            },
          ],
          subtotal: amount,
          total: amount,
        };
        state.invoices.unshift(invoice);
      }
      item.qty = Math.max(0, item.qty - qty);
    });
    saveItems();
    saveInvoices();
    saveCounter();
    state.bulkDraft = null;
    state.formErrors = null;
    state.editingBatchId = null;
    state.editingBatchSnapshot = null;
    viewBulkBatch(batchId);
  }
  function cancelBulkInvoice() {
    if (state.editingBatchId && state.editingBatchSnapshot) {
      // put back the stock that was returned when editing started,
      // since none of the edits are being kept
      var backTo = state.editingBatchId;
      state.editingBatchSnapshot.forEach(function (l) {
        var item = state.items.find(function (i) {
          return i.id === l.itemId;
        });
        if (item) item.qty = Math.max(0, item.qty - l.qty);
      });
      saveItems();
      state.bulkDraft = null;
      state.editingBatchId = null;
      state.editingBatchSnapshot = null;
      state.formErrors = null;
      viewBulkBatch(backTo);
      return;
    }
    state.bulkDraft = null;
    state.formErrors = null;
    goTo("items");
  }

  /* ================= item CRUD ================= */
  function openItemModal(item) {
    state.modal = {
      type: "item",
      payload: item
        ? Object.assign({}, item)
        : {
            id: null,
            name: "",
            img: "",
            qty: 0,
            price: 0,
            unit: "pc",
            cat: "tulip",
            desc: "",
            sku: "",
            unitLabel: "",
            listing: "catalog",
          },
    };
    render();
  }
  async function submitItemModal(formEl) {
    var fd = new FormData(formEl);
    var name = (fd.get("name") || "").toString().trim();
    var qty = Number(fd.get("qty")) || 0;
    var price = Number(fd.get("price")) || 0;
    var images = [1, 2, 3, 4]
      .map(function (n) {
        return (fd.get("img" + n) || "").toString().trim();
      })
      .filter(function (v) {
        return !!v;
      });
    var img = images[0] || "";
    var unit = (fd.get("unit") || "pc").toString();
    var cat = (fd.get("cat") || "tulip").toString();
    var desc = (fd.get("desc") || "").toString().trim();
    var listing = (fd.get("listing") || "catalog").toString();
    var trending = fd.get("trending") === "1";

    function pairedOptions(labelKey, priceKey) {
      var labels = fd.getAll(labelKey);
      var prices = fd.getAll(priceKey);
      var out = [];
      for (var i = 0; i < labels.length; i++) {
        var label = (labels[i] || "").toString().trim();
        if (!label) continue;
        out.push({ label: label, price: Number(prices[i]) || 0 });
      }
      return out;
    }
    var packOptions = pairedOptions("packLabel[]", "packPrice[]");
    var sizeOptions = pairedOptions("sizeLabel[]", "sizePrice[]");
    var colorNames = fd.getAll("colorName[]");
    var colorHexes = fd.getAll("colorHex[]");
    var colorOptions = [];
    for (var ci = 0; ci < colorNames.length; ci++) {
      var cname = (colorNames[ci] || "").toString().trim();
      if (!cname) continue;
      colorOptions.push({
        name: cname,
        hex: (colorHexes[ci] || "#B8842E").toString(),
      });
    }

    if (!name) {
      return;
    }
    var payload = state.modal.payload;
    var newlyCreatedItem = null;
    if (payload.id) {
      var it = state.items.find(function (i) {
        return i.id === payload.id;
      });
      if (it) {
        it.name = name;
        it.qty = qty;
        it.price = price;
        it.img = img;
        it.images = images;
        it.unit = unit;
        it.cat = cat;
        it.desc = desc;
        it.listing = listing;
        it.trending = trending;
        it.packOptions = packOptions;
        it.sizeOptions = sizeOptions;
        it.colorOptions = colorOptions;
        it.color = colorFor(name);
      }
    } else {
      newlyCreatedItem = {
        id: uid(),
        name: name,
        img: img,
        images: images,
        color: colorFor(name),
        qty: qty,
        price: price,
        unit: unit,
        cat: cat,
        desc: desc,
        sku: "",
        unitLabel: "",
        listing: listing,
        trending: trending,
        packOptions: packOptions,
        sizeOptions: sizeOptions,
        colorOptions: colorOptions,
      };
      state.items.push(newlyCreatedItem);
    }
    saveItems();
    if (newlyCreatedItem && state.pendingLineForNewItem && state.draft) {
      var line = state.draft.lines.find(function (l) {
        return l.id === state.pendingLineForNewItem;
      });
      if (line) {
        line.itemId = newlyCreatedItem.id;
        line.query = newlyCreatedItem.name;
      }
    }
    state.pendingLineForNewItem = null;
    state.modal = null;
    render();
  }
  function confirmDeleteItem(id) {
    state.modal = { type: "confirmDeleteItem", payload: { id: id } };
    render();
  }
  async function deleteItem(id) {
    state.items = state.items.filter(function (i) {
      return i.id !== id;
    });
    saveItems();
    state.modal = null;
    render();
  }

  /* ================= category helpers ================= */
  function topLevelCategories() {
    return state.categories.filter(function (c) {
      return !c.parentId;
    });
  }
  function subCategoriesOf(parentId) {
    return state.categories.filter(function (c) {
      return c.parentId === parentId;
    });
  }
  // top-level categories first, each immediately followed by its own
  // sub-categories — used to render the Categories page and the item
  // form's category dropdown in a readable, grouped order.
  function orderedCategories() {
    var out = [];
    var seen = {};
    topLevelCategories().forEach(function (top) {
      out.push({ cat: top, depth: 0 });
      seen[top.id] = true;
      subCategoriesOf(top.id).forEach(function (sub) {
        out.push({ cat: sub, depth: 1 });
        seen[sub.id] = true;
      });
    });
    // safety net: a sub-category whose parent no longer exists shows up
    // as a plain top-level entry instead of silently disappearing
    state.categories.forEach(function (c) {
      if (!seen[c.id]) out.push({ cat: c, depth: 0 });
    });
    return out;
  }

  /* ================= category CRUD ================= */
  function openCategoryModal(cat, presetParentId) {
    state.modal = {
      type: "category",
      payload: cat
        ? Object.assign({}, cat)
        : { id: null, label: "", parentId: presetParentId || null },
    };
    render();
  }
  async function submitCategoryModal(formEl) {
    var fd = new FormData(formEl);
    var label = (fd.get("label") || "").toString().trim();
    if (!label) return;
    var parentRaw = fd.get("parentId");
    var parentId =
      parentRaw !== null && parentRaw !== "" ? parentRaw.toString() : null;
    var payload = state.modal.payload;
    if (payload.id) {
      var existing = state.categories.find(function (c) {
        return c.id === payload.id;
      });
      if (existing) {
        existing.label = label;
        // only apply a parent change if the form actually offered the
        // field (it's hidden for categories that already have children)
        if (parentRaw !== null) existing.parentId = parentId;
      }
    } else {
      var base = slugify(label);
      var id = base;
      var n = 2;
      while (
        state.categories.some(function (c) {
          return c.id === id;
        })
      ) {
        id = base + "-" + n++;
      }
      state.categories.push({ id: id, label: label, parentId: parentId });
    }
    saveCategories();
    state.modal = null;
    render();
  }
  function confirmDeleteCategory(id) {
    var itemCount = state.items.filter(function (i) {
      return i.cat === id;
    }).length;
    var childCount = subCategoriesOf(id).length;
    state.modal = {
      type: "confirmDeleteCategory",
      payload: { id: id, itemCount: itemCount, childCount: childCount },
    };
    render();
  }
  async function deleteCategory(id, reassignTo) {
    if (state.categories.length <= 1) {
      state.modal = null;
      render();
      return;
    }
    if (subCategoriesOf(id).length) {
      state.modal = null;
      render();
      return;
    }
    if (reassignTo) {
      var changed = false;
      state.items.forEach(function (i) {
        if (i.cat === id) {
          i.cat = reassignTo;
          changed = true;
        }
      });
      if (changed) saveItems();
    }
    state.categories = state.categories.filter(function (c) {
      return c.id !== id;
    });
    saveCategories();
    state.modal = null;
    render();
  }

  /* ================= invoice draft editing ================= */
  function addDraftLine() {
    state.draft.lines.push({ id: uid(), itemId: "", qty: 1, query: "" });
    render();
  }
  function removeDraftLine(lineId) {
    if (state.draft.lines.length === 1) return;
    state.draft.lines = state.draft.lines.filter(function (l) {
      return l.id !== lineId;
    });
    render();
  }
  function updateDraftLine(lineId, field, value) {
    var line = state.draft.lines.find(function (l) {
      return l.id === lineId;
    });
    if (!line) return;
    if (field === "itemId") {
      line.itemId = value;
      var item = state.items.find(function (i) {
        return i.id === value;
      });
      line.query = item ? item.name : "";
      // manually re-picking the item means any pack price carried over
      // from a website order no longer applies — fall back to the item's
      // normal price.
      delete line.price;
      delete line.variant;
    }
    if (field === "qty") line.qty = Math.max(0, Number(value) || 0);
    render();
  }
  function updateDraftField(field, value) {
    state.draft[field] = value;
  }

  function selectComboItem(lineId, itemId) {
    state.activeComboLine = null;
    updateDraftLine(lineId, "itemId", itemId);
  }

  /* re-renders just the totals numbers (used instead of a full render()
     while typing, so the subtotal/total stay correct without redrawing
     the whole page) */
  function refreshDraftTotals() {
    var subEl = document.getElementById("draft-subtotal");
    if (subEl) subEl.textContent = fmtMoney(draftSubtotal());
    var delEl = document.getElementById("draft-delivery");
    if (delEl) delEl.textContent = fmtMoney(draftDeliveryCharges());
    var totEl = document.getElementById("draft-total");
    if (totEl) totEl.textContent = fmtMoney(draftTotal());
  }

  /* re-renders a single invoice line row in place (instead of the whole
     app) whenever the item combobox is typed into, focused, or blurred.
     This is the fix for the flicker/"refresh" bug: previously every
     keystroke replaced the entire page's HTML via render(), which caused
     the whole screen (sidebar, images, other rows) to flash on each key
     press. Now only the affected row's markup is swapped out. */
  function updateLineRow(lineId) {
    var rowEl = document.getElementById("line-row-" + lineId);
    var line = state.draft && state.draft.lines.find(function (l) {
      return l.id === lineId;
    });
    if (!rowEl || !line) {
      render();
      return;
    }
    var active = document.activeElement;
    var wasFocused =
      !!active &&
      !!active.getAttribute &&
      active.getAttribute("data-combo-input") === lineId;
    var selStart = null,
      selEnd = null;
    if (wasFocused) {
      try {
        selStart = active.selectionStart;
        selEnd = active.selectionEnd;
      } catch (e) {}
    }
    var wrap = document.createElement("div");
    wrap.innerHTML = buildLineRowHTML(line);
    var newRow = wrap.firstElementChild;
    rowEl.replaceWith(newRow);
    bindLineRowEvents(newRow);
    refreshDraftTotals();
    if (wasFocused) {
      var input = newRow.querySelector("[data-combo-input]");
      if (input) {
        input.focus();
        if (selStart != null) {
          try {
            input.setSelectionRange(selStart, selEnd);
          } catch (e) {}
        }
      }
    }
  }

  function triggerQuickAddItem(lineId, name) {
    state.activeComboLine = null;
    state.pendingLineForNewItem = lineId;
    openItemModal({
      id: null,
      name: name,
      img: "",
      qty: 0,
      price: 0,
      unit: "pc",
      cat: "tulip",
      desc: "",
      sku: "",
      unitLabel: "",
    });
  }

  function draftSubtotal() {
    var total = 0;
    state.draft.lines.forEach(function (l) {
      var item = state.items.find(function (i) {
        return i.id === l.itemId;
      });
      if (item) {
        var unitPrice = typeof l.price === "number" ? l.price : item.price;
        total += unitPrice * l.qty;
      }
    });
    return total;
  }

  function draftDeliveryCharges() {
    return Number(state.draft.deliveryCharges) || 0;
  }

  function draftTotal() {
    return draftSubtotal() + draftDeliveryCharges();
  }

  function draftErrors() {
    var errs = [];
    if (!state.draft.clientName.trim()) errs.push("Client name is required.");
    var validLines = state.draft.lines.filter(function (l) {
      return l.itemId;
    });
    if (validLines.length === 0) errs.push("Add at least one item.");
    validLines.forEach(function (l) {
      var item = state.items.find(function (i) {
        return i.id === l.itemId;
      });
      if (item && l.qty > item.qty) {
        errs.push(
          "Only " +
            item.qty +
            " " +
            unitLabel(item.unit) +
            " of " +
            item.name +
            " in stock.",
        );
      }
      if (item && l.qty <= 0) {
        errs.push("Quantity for " + item.name + " must be greater than 0.");
      }
    });
    return errs;
  }

  async function saveDraftInvoice() {
    var errs = draftErrors();
    if (errs.length) {
      state.formErrors = errs;
      render();
      return;
    }
    var lines = state.draft.lines
      .filter(function (l) {
        return l.itemId;
      })
      .map(function (l) {
        var item = state.items.find(function (i) {
          return i.id === l.itemId;
        });
        var unitPrice = typeof l.price === "number" ? l.price : item.price;
        return {
          itemId: item.id,
          name: item.name + (l.variant ? " (" + l.variant + ")" : ""),
          img: item.img,
          color: item.color,
          unit: item.unit,
          variant: l.variant || "",
          qty: l.qty,
          price: unitPrice,
          amount: unitPrice * l.qty,
        };
      });
    var subtotal = lines.reduce(function (s, l) {
      return s + l.amount;
    }, 0);
    var deliveryCharges = Number(state.draft.deliveryCharges) || 0;
    var total = subtotal + deliveryCharges;

    lines.forEach(function (l) {
      var item = state.items.find(function (i) {
        return i.id === l.itemId;
      });
      if (item) item.qty = Math.max(0, item.qty - l.qty);
    });

    var savedId;
    if (state.editingInvoiceId) {
      var existing = state.invoices.find(function (i) {
        return i.id === state.editingInvoiceId;
      });
      if (existing) {
        existing.date = state.draft.date;
        existing.deliveryCharges = deliveryCharges;
        existing.clientName = state.draft.clientName.trim();
        existing.phone = state.draft.phone.trim();
        existing.address = state.draft.address.trim();
        existing.lines = lines;
        existing.subtotal = subtotal;
        existing.total = total;
        savedId = existing.id;
      }
      state.editingInvoiceId = null;
      state.editingSnapshot = null;
    } else {
      var invoice = {
        id: uid(),
        invoiceNo: state.draft.invoiceNo,
        deliveryCharges: deliveryCharges,
        date: state.draft.date,
        clientName: state.draft.clientName.trim(),
        phone: state.draft.phone.trim(),
        address: state.draft.address.trim(),
        lines: lines,
        subtotal: subtotal,
        total: total,
      };
      state.invoices.unshift(invoice);
      savedId = invoice.id;
    }

    saveItems();
    saveInvoices();
    saveCounter();
    if (state.draft.sourceOrderId) {
      setOrderStatus(state.draft.sourceOrderId, "billed", {
        invoiceId: savedId,
      });
    }
    state.draft = null;
    state.formErrors = null;
    state.activeInvoiceId = savedId;
    state.view = "invoice-view";
    render();
  }

  function cancelDraft() {
    if (state.editingInvoiceId) {
      var backToId = state.editingInvoiceId;
      abandonEditIfAny();
      state.draft = null;
      state.formErrors = null;
      state.activeInvoiceId = backToId;
      state.view = "invoice-view";
      render();
      return;
    }
    state.draft = null;
    state.formErrors = null;
    goTo("dashboard");
  }

  function editInvoice(id) {
    var inv = state.invoices.find(function (i) {
      return i.id === id;
    });
    if (!inv) return;
    // put this invoice's quantities back into stock so they can be re-allocated / adjusted
    inv.lines.forEach(function (l) {
      var item = state.items.find(function (i) {
        return i.id === l.itemId;
      });
      if (item) item.qty += l.qty;
    });
    saveItems();
    state.editingInvoiceId = inv.id;
    state.editingSnapshot = inv.lines.map(function (l) {
      return { itemId: l.itemId, qty: l.qty };
    });
    state.draft = {
      invoiceNo: inv.invoiceNo,
      deliveryCharges: inv.deliveryCharges || 0,
      date: inv.date,
      clientName: inv.clientName,
      phone: inv.phone || "",
      address: inv.address || "",
      lines: inv.lines.map(function (l) {
        var item = state.items.find(function (i) {
          return i.id === l.itemId;
        });
        // preserve the price this line was actually billed at, so editing
        // an invoice that had a pack price on it doesn't quietly reset
        // back to the item's normal single-piece price.
        var carriedPrice =
          item && typeof l.price === "number" && l.price !== item.price
            ? l.price
            : undefined;
        return {
          id: uid(),
          itemId: l.itemId,
          qty: l.qty,
          query: item ? item.name : l.name || "",
          price: carriedPrice,
          // carry the pack/variant label forward too, otherwise editing a
          // pack order and saving again silently drops the "(3 Pc)" style
          // label from the name and the bill's quantity column.
          variant: l.variant || "",
        };
      }),
    };
    state.formErrors = null;
    state.view = "new-invoice";
    render();
  }

  function viewInvoice(id) {
    state.activeInvoiceId = id;
    state.view = "invoice-view";
    render();
  }
  function confirmDeleteInvoice(id) {
    state.modal = { type: "confirmDeleteInvoice", payload: { id: id } };
    render();
  }
  async function deleteInvoice(id) {
    var inv = state.invoices.find(function (i) {
      return i.id === id;
    });
    if (inv) {
      // restore stock for the deleted invoice's lines
      inv.lines.forEach(function (l) {
        var item = state.items.find(function (i) {
          return i.id === l.itemId;
        });
        if (item) item.qty += l.qty;
      });
      saveItems();
    }
    state.invoices = state.invoices.filter(function (i) {
      return i.id !== id;
    });
    saveInvoices();
    state.modal = null;
    if (state.activeInvoiceId === id) {
      state.activeInvoiceId = null;
      state.view = "invoices";
    }
    render();
  }

  function viewClientInvoices(clientName) {
    state.clientFilter = clientName;
    state.monthFilter = null;
    state.rangeFilter = null;
    state.view = "invoices";
    render();
  }

  function viewMonthInvoices(monthKey) {
    state.monthFilter = monthKey;
    state.clientFilter = null;
    state.rangeFilter = null;
    state.view = "invoices";
    render();
  }

  function viewRangeInvoices(from, to) {
    state.rangeFilter = { from: from || "", to: to || "" };
    state.clientFilter = null;
    state.monthFilter = null;
    state.view = "invoices";
    render();
  }

  function viewItemOrders(itemId) {
    state.activeItemId = itemId;
    state.view = "item-orders";
    render();
  }

  /* ================= render helpers ================= */
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      }[c];
    });
  }

  function beadsDivider() {
    var colors = ["var(--gold)", "var(--teal)", "var(--gold)", "var(--maroon)"];
    var dots = "";
    for (var i = 0; i < 28; i++) {
      dots +=
        '<span style="background:' + colors[i % colors.length] + '"></span>';
    }
    return '<div class="beads">' + dots + "</div>";
  }

  function invoiceFooterHTML() {
    return '<div class="inv-footer">JSK CREATION<span class="dot-sep"></span>Beads &amp; Jewellery Supply</div>';
  }

  function renderSidebar() {
    var pendingCount = pendingOrders().length;
    var navItems = [
      { id: "dashboard", label: "Dashboard" },
      { id: "orders", label: "Naya Order", badge: pendingCount },
      { id: "items", label: "Inventory" },
      { id: "categories", label: "Categories" },
      { id: "new-invoice", label: "New Invoice" },
      { id: "invoices", label: "Invoice History" },
      { id: "earnings", label: "Monthly Earnings" },
      { id: "bulk-orders", label: "Multi-Client Orders" },
      { id: "clients", label: "Clients" },
    ];
    var buttons = navItems
      .map(function (n) {
        var active =
          state.view === n.id ||
          (state.view === "invoice-view" && n.id === "invoices") ||
          (state.view === "item-orders" && n.id === "items") ||
          (state.view === "bulk-invoice" && n.id === "bulk-orders") ||
          (state.view === "bulk-order-view" && n.id === "bulk-orders");
        return (
          '<button class="' +
          (active ? "active" : "") +
          '" data-nav="' +
          n.id +
          '"><span class="dot"></span>' +
          n.label +
          (n.badge
            ? '<span class="pill low" style="margin-left:8px;">' +
              n.badge +
              "</span>"
            : "") +
          "</button>"
        );
      })
      .join("");
    return (
      '<div class="sidebar no-print">' +
      '<div style="display:flex;align-items:center;gap:10px;"><img src="logo-mark.png" alt="JSK Creation" class="brand-mark"></div>' +
      '<div class="nav">' +
      buttons +
      "</div>" +
      '<a href="index.html" class="back-to-store">&larr; Back to Store</a>' +
      '<div class="sidebar-foot">' +
      state.invoices.length +
      " invoices billed<br>" +
      state.items.length +
      " items tracked</div>" +
      '<div class="sidebar-auth-row">' +
      '<button type="button" class="btn-link" data-change-password>Change Password</button>' +
      '<button type="button" class="btn-link" data-logout>Logout</button>' +
      "</div>" +
      "</div>"
    );
  }

  function fmtDateTime(iso) {
    if (!iso) return "";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    return d.toLocaleString("en-IN", {
      day: "2-digit",
      month: "short",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  function renderOrders() {
    var pending = pendingOrders();
    var recentOther = state.orders
      .filter(function (o) {
        return o.status !== "pending";
      })
      .slice(0, 15);

    function orderCard(o, showActions) {
      var cust = o.customer || {};
      var lines = o.lines || [];
      var itemsHtml = lines
        .map(function (l) {
          return (
            "<tr><td>" +
            esc(l.name || "Item") +
            // show which pack/variant was ordered right here too, so a
            // pack order (e.g. "3 Pc") is clear before it's even billed —
            // not just after, on the generated invoice.
            (l.variant ? ' <span class="muted">(' + esc(l.variant) + ")</span>" : "") +
            (l.preorder
              ? ' <span class="pill" style="background:#f3ece1;color:#8a6a3e;">pre-book · 2–4 wks</span>'
              : "") +
            "</td><td>" +
            l.qty +
            '</td><td class="num">' +
            fmtMoney((l.price || 0) * (l.qty || 0)) +
            "</td></tr>"
          );
        })
        .join("");
      var statusPill =
        o.status === "billed"
          ? '<span class="pill" style="background:#e6f4ea;color:#1f6e43;">billed</span>'
          : o.status === "dismissed"
            ? '<span class="pill low">dismissed</span>'
            : '<span class="pill low">pending</span>';
      var preorderPill = o.hasPreorder
        ? ' <span class="pill" style="background:#f3ece1;color:#8a6a3e;">pre-booking</span>'
        : "";
      return (
        '<div class="card" style="margin-bottom:16px;">' +
        '<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;flex-wrap:wrap;">' +
        "<div>" +
        '<h3 class="display" style="margin:0 0 4px;font-size:17px;">' +
        esc(cust.name || "Unknown customer") +
        " " +
        statusPill +
        preorderPill +
        "</h3>" +
        '<div class="muted">' +
        esc(cust.phone || "") +
        (cust.address || cust.city
          ? " &middot; " + esc([cust.address, cust.city].filter(Boolean).join(", "))
          : "") +
        "</div>" +
        (cust.notes
          ? '<div class="muted" style="margin-top:4px;">Note: ' + esc(cust.notes) + "</div>"
          : "") +
        "</div>" +
        '<div style="text-align:right;">' +
        '<div class="muted">' +
        fmtDateTime(o.createdAt) +
        "</div>" +
        '<div class="value teal" style="font-size:18px;">' +
        fmtMoney(o.total) +
        "</div>" +
        "</div>" +
        "</div>" +
        '<div class="table-wrap" style="margin-top:10px;"><table><thead><tr><th>Item</th><th>Qty</th><th>Amount</th></tr></thead><tbody>' +
        itemsHtml +
        "</tbody></table></div>" +
        (showActions
          ? '<div class="btn-row" style="margin-top:12px;">' +
            '<button class="btn btn-primary" data-bill-order="' +
            o.id +
            '">Bill Banayen</button>' +
            '<button class="btn btn-ghost" data-dismiss-order="' +
            o.id +
            '">Dismiss</button>' +
            "</div>"
          : "") +
        "</div>"
      );
    }

    return (
      '<div class="page-head">' +
      "<div><h1>Naya Order</h1><p>Website se aane wale orders yahan live aate hain. Har order check karke bill banayein.</p></div>" +
      "</div>" +
      beadsDivider() +
      (pending.length
        ? pending.map(function (o) { return orderCard(o, true); }).join("")
        : '<div class="empty"><div class="glyph">🧾</div><h3>Koi naya order nahi</h3><p>Jab customer website se order karega, wo yahan turant aa jayega.</p></div>') +
      (recentOther.length
        ? '<h3 class="display" style="margin:24px 0 12px;font-size:16px;">Purane Orders</h3>' +
          recentOther.map(function (o) { return orderCard(o, false); }).join("")
        : "")
    );
  }

  function renderDashboard() {
    var stockValue = state.items.reduce(function (s, i) {
      return s + i.qty * i.price;
    }, 0);
    var revenue = state.invoices.reduce(function (s, i) {
      return s + i.total;
    }, 0);
    var lowStock = state.items.filter(function (i) {
      return i.qty <= 5;
    });
    var recent = state.invoices.slice(0, 5);
    var pendingCount = pendingOrders().length;

    var months = monthlyEarnings();
    var thisKey = new Date().toISOString().slice(0, 7);
    var thisMonthObj = months.find(function (m) {
      return m.key === thisKey;
    });

    var recentRows = recent
      .map(function (inv) {
        return (
          "<tr>" +
          '<td><div style="display:flex;align-items:center;gap:10px;">' +
          '<div class="avatar-circle" style="background:' +
          colorFor(inv.clientName) +
          ';">' +
          initials(inv.clientName) +
          "</div>" +
          '<div><div class="item-name">' +
          esc(inv.clientName) +
          '</div><div class="muted">' +
          esc(inv.invoiceNo) +
          "</div></div>" +
          "</div></td>" +
          "<td>" +
          fmtDate(inv.date) +
          "</td>" +
          '<td><span class="pill ok">Billed</span></td>' +
          '<td class="num">' +
          fmtMoney(inv.total) +
          "</td>" +
          '<td><button class="btn btn-ghost" data-view-invoice="' +
          inv.id +
          '" style="padding:6px 12px;font-size:12px;">View</button></td>' +
          "</tr>"
        );
      })
      .join("");

    var lowStockHtml = lowStock.length
      ? lowStock
          .map(function (i) {
            return (
              '<tr><td class="item-name" style="display:flex;align-items:center;gap:10px;">' +
              thumbHTML(i, 28) +
              " " +
              esc(i.name) +
              '</td><td><span class="pill low">' +
              i.qty +
              " " +
              unitLabel(i.unit) +
              " left</span></td></tr>"
            );
          })
          .join("")
      : '<tr><td class="muted" style="padding:14px 10px;">All items are well stocked.</td></tr>';

    return (
      '<div class="page-head">' +
      "<div><h1>Dashboard</h1><p>Overview of stock and billing for JSK Creation.</p></div>" +
      '<button class="btn btn-primary" data-nav="new-invoice">+ New Invoice</button>' +
      "</div>" +
      beadsDivider() +
      '<div class="card dash-hero" data-nav="earnings" style="cursor:pointer;">' +
      '<div class="dash-hero-row">' +
      "<div>" +
      '<div class="label">Total Revenue</div>' +
      '<div class="dash-hero-value">' +
      fmtMoney(revenue) +
      "</div>" +
      '<div style="margin-top:10px;display:flex;align-items:center;gap:8px;">' +
      changePillHtml(thisMonthObj) +
      '<span class="muted">vs last month</span>' +
      "</div>" +
      "</div>" +
      '<div class="dash-hero-link muted">See Monthly Earnings →</div>' +
      "</div>" +
      "</div>" +
      '<div class="grid stat-grid" style="margin-top:20px;">' +
      '<div class="stat" style="cursor:pointer;" data-nav="orders"><div class="label">Naya Order</div><div class="value' +
      (pendingCount ? " teal" : "") +
      '">' +
      pendingCount +
      "</div></div>" +
      '<div class="stat"><div class="label">Items Tracked</div><div class="value">' +
      state.items.length +
      "</div></div>" +
      '<div class="stat"><div class="label">Stock Value</div><div class="value teal">' +
      fmtMoney(stockValue) +
      "</div></div>" +
      '<div class="stat" style="cursor:pointer;" data-nav="invoices"><div class="label">Invoices Billed</div><div class="value">' +
      state.invoices.length +
      "</div></div>" +
      "</div>" +
      '<div class="grid" style="grid-template-columns:1.4fr 1fr; margin-top:28px; align-items:start;">' +
      '<div class="card">' +
      '<h3 class="display" style="margin:0 0 12px;font-size:17px;">Recent Invoices</h3>' +
      (recent.length
        ? '<div class="table-wrap"><table><tbody>' +
          recentRows +
          "</tbody></table></div>"
        : '<div class="empty"><div class="glyph">🧾</div><h3>No invoices yet</h3><p>Create your first invoice to see it here.</p></div>') +
      "</div>" +
      '<div class="card">' +
      '<h3 class="display" style="margin:0 0 12px;font-size:17px;">Low Stock</h3>' +
      '<div class="table-wrap"><table><tbody>' +
      lowStockHtml +
      "</tbody></table></div>" +
      "</div>" +
      "</div>"
    );
  }

  function renderItems() {
    var query = (state.itemSearchQuery || "").trim().toLowerCase();
    var filteredItems = query
      ? state.items.filter(function (i) {
          var words = i.name.toLowerCase().split(/\s+/);
          return (
            i.name.toLowerCase().indexOf(query) > -1 ||
            words.some(function (w) {
              return w.indexOf(query) === 0;
            })
          );
        })
      : state.items;

    var rows = filteredItems
      .map(function (i) {
        var low = i.qty <= 5;
        var out = i.qty <= 0;
        return (
          "<tr>" +
          '<td style="width:44px;">' +
          thumbHTML(i, 40) +
          "</td>" +
          '<td class="item-name">' +
          esc(i.name) +
          (i.listing === "prebook"
            ? ' <span class="pill" style="background:#f3ece1;color:#8a6a3e;">pre-booking</span>'
            : "") +
          (i.trending
            ? ' <span class="pill" style="background:#fbeecb;color:#8a5a10;">⭐ trending</span>'
            : "") +
          '<div class="muted">' +
          categoryLabel(i.cat) +
          (i.sku ? " &middot; " + esc(i.sku) : "") +
          "</div></td>" +
          "<td>" +
          i.qty +
          " " +
          unitLabel(i.unit) +
          " " +
          (out
            ? '<span class="pill low" style="margin-left:8px;">out of stock</span>'
            : low
              ? '<span class="pill low" style="margin-left:8px;">low</span>'
              : "") +
          "</td>" +
          '<td class="num">' +
          fmtMoney(i.price) +
          " / " +
          unitLabel(i.unit) +
          "</td>" +
          '<td class="num">' +
          fmtMoney(i.qty * i.price) +
          "</td>" +
          '<td style="text-align:right; white-space:nowrap;">' +
          '<button class="btn btn-ghost" data-view-orders="' +
          i.id +
          '" style="padding:6px 12px;font-size:12px;">View Orders</button> ' +
          '<button class="btn btn-ghost" data-edit-item="' +
          i.id +
          '" style="padding:6px 12px;font-size:12px;">Edit</button> ' +
          '<button class="btn btn-danger" data-del-item="' +
          i.id +
          '" style="padding:6px 12px;font-size:12px;">Delete</button>' +
          "</td>" +
          "</tr>"
        );
      })
      .join("");

    var emptyState = state.items.length
      ? '<div class="empty"><div class="glyph">🔎</div><h3>No matches</h3><p>No items match "' +
        esc(state.itemSearchQuery) +
        '".</p></div>'
      : '<div class="empty"><div class="glyph">📦</div><h3>No items yet</h3><p>Add your first item to start building invoices.</p></div>';

    return (
      '<div class="page-head">' +
      "<div><h1>Inventory</h1><p>Items you stock. These are the exact same items shown live on the website — edit stock, price or details here and the site updates automatically.</p></div>" +
      '<div class="btn-row">' +
      '<div class="icon-field" style="width:230px;">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>' +
      '<input type="text" data-item-search value="' +
      esc(state.itemSearchQuery || "") +
      '" placeholder="Search items…">' +
      "</div>" +
      '<button class="btn btn-ghost" data-new-bulk-invoice>+ Multi-Client Order</button>' +
      '<button class="btn btn-gold" data-add-item>+ Add Item</button>' +
      "</div>" +
      "</div>" +
      beadsDivider() +
      '<div class="card">' +
      (filteredItems.length
        ? '<div class="table-wrap"><table><thead><tr><th></th><th>Item Name</th><th>Quantity We Have</th><th>Price per pc</th><th>Stock Value</th><th></th></tr></thead><tbody>' +
          rows +
          "</tbody></table></div>"
        : emptyState) +
      "</div>"
    );
  }

  function renderCategories() {
    var rows = orderedCategories()
      .map(function (entry) {
        var c = entry.cat;
        var count = state.items.filter(function (i) {
          return i.cat === c.id;
        }).length;
        var childCount = subCategoriesOf(c.id).length;
        return (
          "<tr>" +
          '<td class="item-name" style="' +
          (entry.depth ? "padding-left:34px;" : "") +
          '">' +
          (entry.depth ? "↳ " : "") +
          esc(c.label) +
          '<div class="muted">' +
          esc(c.id) +
          (childCount
            ? " &middot; " + childCount + " sub-categor" + (childCount === 1 ? "y" : "ies")
            : "") +
          "</div></td>" +
          "<td>" +
          count +
          " item" +
          (count === 1 ? "" : "s") +
          "</td>" +
          '<td style="text-align:right; white-space:nowrap;">' +
          (entry.depth === 0
            ? '<button class="btn btn-ghost" data-add-subcategory="' +
              c.id +
              '" style="padding:6px 12px;font-size:12px;">+ Sub-category</button> '
            : "") +
          '<button class="btn btn-ghost" data-edit-category="' +
          c.id +
          '" style="padding:6px 12px;font-size:12px;">Edit</button> ' +
          '<button class="btn btn-danger" data-del-category="' +
          c.id +
          '" style="padding:6px 12px;font-size:12px;">Delete</button>' +
          "</td>" +
          "</tr>"
        );
      })
      .join("");

    return (
      '<div class="page-head">' +
      "<div><h1>Categories</h1><p>These are the exact categories shown on the website's Shop By Category menu and in the item form below — add, rename, nest, or remove one and the site updates automatically.</p></div>" +
      '<button class="btn btn-gold" data-add-category>+ Add Category</button>' +
      "</div>" +
      beadsDivider() +
      '<div class="card">' +
      (state.categories.length
        ? '<div class="table-wrap"><table><thead><tr><th>Category</th><th>Items</th><th></th></tr></thead><tbody>' +
          rows +
          "</tbody></table></div>"
        : '<div class="empty"><div class="glyph">🏷️</div><h3>No categories yet</h3><p>Add your first category.</p></div>') +
      "</div>"
    );
  }

  /* builds the markup for a single invoice line row; kept standalone (rather
     than inline in renderNewInvoice) so a single row can be re-rendered on
     its own while the item combobox is being typed into — re-rendering the
     whole page on every keystroke is what was causing the flicker/"refresh"
     bug when adding items to an invoice */
  function buildLineRowHTML(l) {
    var item = state.items.find(function (i) {
      return i.id === l.itemId;
    });
    var unitPrice = item ? (typeof l.price === "number" ? l.price : item.price) : 0;
    var amount = item ? unitPrice * l.qty : 0;
    var query = item ? item.name : l.query || "";
    var isActive = state.activeComboLine === l.id;
    var hasExact = state.items.some(function (i) {
      return i.name.trim().toLowerCase() === query.trim().toLowerCase();
    });
    var listHtml = "";
    if (isActive) {
      var matches = comboFilter(state.items, query).slice(0, 8);
      listHtml += matches
        .map(function (i) {
          return (
            '<div class="combo-item" data-combo-pick="' +
            l.id +
            '" data-combo-item-id="' +
            i.id +
            '">' +
            thumbHTML(i, 24) +
            '<div class="combo-item-text"><div class="combo-item-name">' +
            esc(i.name) +
            '</div><div class="muted" style="font-size:11px;">' +
            i.qty +
            " " +
            unitLabel(i.unit) +
            " left &middot; " +
            fmtMoney(i.price) +
            "/" +
            unitLabel(i.unit) +
            "</div></div>" +
            "</div>"
          );
        })
        .join("");
      if (query.trim() && !hasExact) {
        listHtml +=
          '<div class="combo-item combo-add" data-combo-quickadd="' +
          l.id +
          '" data-combo-quickadd-name="' +
          esc(query.trim()) +
          '">+ Add "' +
          esc(query.trim()) +
          '" as new item</div>';
      }
      if (!matches.length && !query.trim()) {
        listHtml += '<div class="combo-empty muted">Type to search items…</div>';
      }
    }
    return (
      '<div class="line-item-row" id="line-row-' +
      l.id +
      '">' +
      '<div class="combo">' +
      '<input type="text" class="combo-input" data-combo-input="' +
      l.id +
      '" value="' +
      esc(query) +
      '" placeholder="Type item name…" autocomplete="off">' +
      (isActive ? '<div class="combo-list">' + listHtml + "</div>" : "") +
      "</div>" +
      '<input type="number" min="0" step="1" value="' +
      l.qty +
      '" data-line="' +
      l.id +
      '" data-field="qty">' +
      '<div class="muted" style="text-align:right;">' +
      (item
        ? fmtMoney(unitPrice) + "/" + (l.variant || unitLabel(item.unit))
        : "—") +
      "</div>" +
      '<div class="amt">' +
      fmtMoney(amount) +
      "</div>" +
      '<button class="remove-row" data-remove-line="' +
      l.id +
      '" title="Remove">✕</button>' +
      "</div>"
    );
  }

  function renderNewInvoice() {
    if (!state.draft) startDraft();
    var d = state.draft;

    var lineRows = d.lines.map(buildLineRowHTML).join("");

    var errs = state.formErrors;
    var errHtml =
      errs && errs.length
        ? '<div style="background:#FBEEEA;border:1px solid #EAD3CC;color:var(--danger);padding:12px 14px;border-radius:8px;font-size:13px;margin-bottom:16px;">' +
          errs.map(esc).join("<br>") +
          "</div>"
        : "";

    return (
      '<div class="page-head">' +
      "<div><h1>" +
      (state.editingInvoiceId ? "Edit Invoice" : "New Invoice") +
      "</h1><p>Invoice " +
      esc(d.invoiceNo) +
      " · " +
      fmtDate(d.date) +
      "</p></div>" +
      '<div class="btn-row">' +
      '<button class="btn btn-ghost" data-cancel-draft>Cancel</button>' +
      '<button class="btn btn-primary" data-save-draft>' +
      (state.editingInvoiceId ? "Save Changes" : "Save &amp; View Invoice") +
      "</button>" +
      "</div>" +
      "</div>" +
      beadsDivider() +
      errHtml +
      '<div class="grid" style="grid-template-columns:1fr 1fr;">' +
      '<div class="card">' +
      '<h3 class="display" style="margin:0 0 14px;font-size:16px;">Client Details</h3>' +
      '<div class="field"><label>Client Name</label><div class="icon-field">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>' +
      '<input type="text" data-draft-field="clientName" value="' +
      esc(d.clientName) +
      '" placeholder="e.g. Yash Gota">' +
      "</div></div>" +
      '<div class="field-row">' +
      '<div class="field"><label>Phone Number</label><div class="icon-field">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg>' +
      '<input type="text" data-draft-field="phone" value="' +
      esc(d.phone) +
      '" placeholder="03xx-xxxxxxx">' +
      "</div></div>" +
      '<div class="field"><label>Date</label><div class="icon-field">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg>' +
      '<input type="date" data-draft-field="date" value="' +
      d.date +
      '">' +
      "</div></div>" +
      "</div>" +
      '<div class="field"><label>Client Address</label><div class="icon-field">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0z"/><circle cx="12" cy="10" r="3"/></svg>' +
      '<input type="text" data-draft-field="address" value="' +
      esc(d.address) +
      '" placeholder="Shop / city">' +
      "</div></div>" +
      "</div>" +
      '<div class="card">' +
      '<h3 class="display" style="margin:0 0 14px;font-size:16px;">Invoice Meta</h3>' +
      '<div class="field"><label>Invoice No.</label><div class="prefix-input"><span class="prefix-tag">JSK</span><input type="text" value="' +
      esc(d.invoiceNo.replace(/^JSK-/, "")) +
      '" disabled></div></div>' +
      '<div class="field"><label>Delivery Charges</label><div class="prefix-input"><span class="prefix-tag">Rs.</span><input type="number" min="0" step="1" data-draft-field="deliveryCharges" value="' +
      (Number(d.deliveryCharges) || 0) +
      '" placeholder="0"></div></div>' +
      '<p class="field-hint">Invoice numbers are generated automatically in sequence.</p>' +
      "</div>" +
      "</div>" +
      '<div class="card" style="margin-top:20px;">' +
      '<h3 class="display" style="margin:0 0 14px;font-size:16px;">Items</h3>' +
      (state.items.length
        ? '<div class="line-item-row muted" style="font-size:11px;text-transform:uppercase;letter-spacing:0.06em;"><div>Item</div><div>Qty</div><div style="text-align:right;">Price</div><div style="text-align:right;">Amount</div><div></div></div>' +
          lineRows +
          '<button class="add-row-btn" data-add-line>+ Add another item</button>'
        : '<div class="empty"><div class="glyph">📦</div><h3>No items in inventory</h3><p>Add items in the Inventory tab first.</p></div>') +
      '<div class="totals-box"><div class="row" style="flex-direction:column; align-items:flex-end; gap:6px;">' +
      '<div style="display:flex; gap:26px; align-items:baseline;"><span class="lbl">Items Subtotal</span><span class="muted num" id="draft-subtotal">' +
      fmtMoney(draftSubtotal()) +
      "</span></div>" +
      '<div style="display:flex; gap:26px; align-items:baseline;"><span class="lbl">Delivery Charges</span><span class="muted num" id="draft-delivery">' +
      fmtMoney(draftDeliveryCharges()) +
      "</span></div>" +
      '<div style="display:flex; gap:26px; align-items:baseline;"><span class="lbl">Total Price</span><span class="amt" id="draft-total">' +
      fmtMoney(draftTotal()) +
      "</span></div>" +
      "</div></div>" +
      "</div>"
    );
  }

  /* returns invoices grouped into calendar months, oldest first, each with
     total earned, invoice count, and % change vs the previous month —
     used to power the Monthly Earnings page (chart + up/down trend) */
  function monthlyEarnings() {
    var map = {};
    state.invoices.forEach(function (inv) {
      var key = (inv.date || "").slice(0, 7);
      if (!key) return;
      if (!map[key]) map[key] = { key: key, total: 0, count: 0 };
      map[key].total += inv.total;
      map[key].count += 1;
    });
    var list = Object.keys(map).map(function (k) {
      return map[k];
    });
    list.sort(function (a, b) {
      return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
    });
    list.forEach(function (m, idx) {
      m.label = new Date(m.key + "-01T00:00:00").toLocaleDateString("en-IN", {
        month: "short",
        year: "numeric",
      });
      if (idx > 0) {
        var prevTotal = list[idx - 1].total;
        m.hasPrev = true;
        if (prevTotal > 0) {
          m.change = ((m.total - prevTotal) / prevTotal) * 100;
        } else {
          m.change = m.total > 0 ? 100 : 0;
        }
      } else {
        m.hasPrev = false;
        m.change = 0;
      }
    });
    return list;
  }

  /* small "▲ 4.2%" / "▼ 1.1%" trend pill, shared between the Dashboard and
     the Monthly Earnings page */
  function changePillHtml(m) {
    if (!m || !m.hasPrev) {
      return '<span class="pill" style="background:var(--line);color:#8A7A6B;">— New</span>';
    }
    var up = m.change >= 0;
    return (
      '<span class="pill ' +
      (up ? "ok" : "low") +
      '">' +
      (up ? "▲ " : "▼ ") +
      Math.abs(m.change).toFixed(1) +
      "%</span>"
    );
  }

  /* ---------- Shopify-style sales chart (smooth curve + gradient fill) ---------- */

  /* smooth curve through points using a Catmull-Rom -> cubic-bezier conversion */
  function smoothLinePath(pts) {
    if (!pts.length) return "";
    if (pts.length === 1) {
      return "M " + pts[0].x.toFixed(2) + " " + pts[0].y.toFixed(2);
    }
    var d = "M " + pts[0].x.toFixed(2) + " " + pts[0].y.toFixed(2);
    for (var i = 0; i < pts.length - 1; i++) {
      var p0 = pts[i === 0 ? 0 : i - 1];
      var p1 = pts[i];
      var p2 = pts[i + 1];
      var p3 = pts[i + 2 < pts.length ? i + 2 : i + 1];
      var c1x = p1.x + (p2.x - p0.x) / 6;
      var c1y = p1.y + (p2.y - p0.y) / 6;
      var c2x = p2.x - (p3.x - p1.x) / 6;
      var c2y = p2.y - (p3.y - p1.y) / 6;
      d +=
        " C " +
        c1x.toFixed(2) +
        " " +
        c1y.toFixed(2) +
        ", " +
        c2x.toFixed(2) +
        " " +
        c2y.toFixed(2) +
        ", " +
        p2.x.toFixed(2) +
        " " +
        p2.y.toFixed(2);
    }
    return d;
  }

  /* rounds a max value up to a "nice" number so gridlines read cleanly (0 / half / max) */
  function niceCeil(n) {
    if (!n || n <= 0) return 1;
    var mag = Math.pow(10, Math.floor(Math.log10(n)));
    var norm = n / mag;
    var niceNorm = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10;
    return niceNorm * mag;
  }

  /* compact currency for axis labels: Rs. 5K / Rs. 1.2M */
  function shortMoney(n) {
    n = Number(n) || 0;
    var sign = n < 0 ? "-" : "";
    n = Math.abs(n);
    var trim = function (v) {
      return (Math.round(v * 10) / 10).toString();
    };
    if (n >= 1000000) return sign + "Rs. " + trim(n / 1000000) + "M";
    if (n >= 1000) return sign + "Rs. " + trim(n / 1000) + "K";
    return sign + "Rs. " + trim(n);
  }

  /* builds a full Shopify-style "Total Sales" card: big number, trend badge,
     smooth gradient-area chart with an optional dotted previous-period line,
     and a small legend underneath. months = monthlyEarnings() list. */
  function shopifySalesCardHtml(months, title) {
    var current = months.slice(-12);
    var previous = months.slice(-24, -12);

    var curTotal = current.reduce(function (s, m) {
      return s + m.total;
    }, 0);
    var prevTotal = previous.reduce(function (s, m) {
      return s + m.total;
    }, 0);
    var periodChange = prevTotal > 0 ? ((curTotal - prevTotal) / prevTotal) * 100 : curTotal > 0 ? 100 : 0;
    var periodUp = periodChange >= 0;
    var hasComparison = previous.length > 0;

    var headHtml =
      '<div class="shopify-card-head">' +
      '<div class="shopify-card-title">' +
      esc(title || "Total Sales") +
      "</div>" +
      '<svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="shopify-card-icon"><path d="M3 3v18h18"/><path d="M18.7 8-13 13.5 8.5 10 3 15.5"/></svg>' +
      "</div>" +
      '<div class="shopify-card-value-row">' +
      '<div class="shopify-card-value">' +
      fmtMoney(curTotal) +
      "</div>" +
      (hasComparison
        ? '<div class="shopify-card-change ' +
          (periodUp ? "up" : "down") +
          '">' +
          (periodUp ? "↑ " : "↓ ") +
          Math.abs(periodChange).toFixed(0) +
          "%</div>"
        : "") +
      "</div>";

    if (current.length < 2) {
      return (
        headHtml +
        '<div class="empty" style="padding:30px 10px;"><div class="glyph">📈</div><h3>Not enough data yet</h3><p>Save a couple of invoices to see your sales trend here.</p></div>'
      );
    }

    var padL = 8,
      padR = 8,
      padT = 10,
      padB = 10,
      vbW = 1000,
      vbH = 240;
    var plotW = vbW - padL - padR;
    var plotH = vbH - padT - padB;
    var allTotals = current
      .map(function (m) {
        return m.total;
      })
      .concat(
        previous.map(function (m) {
          return m.total;
        })
      );
    var niceMax = niceCeil(Math.max.apply(null, allTotals.concat([0])));

    function toPoints(arr) {
      var n = arr.length;
      return arr.map(function (m, i) {
        var x = n > 1 ? padL + (i * plotW) / (n - 1) : padL + plotW / 2;
        var ratio = niceMax ? m.total / niceMax : 0;
        var y = padT + (1 - ratio) * plotH;
        return { x: x, y: y, m: m };
      });
    }

    var curPts = toPoints(current);
    var prevPts = toPoints(previous);
    var curLineD = smoothLinePath(curPts);
    var prevLineD = prevPts.length > 1 ? smoothLinePath(prevPts) : "";
    var baseY = padT + plotH;
    var curveTail = curLineD.replace(/^M [^ ]+ [^ ]+ /, "");
    var curAreaD =
      "M " +
      curPts[0].x.toFixed(2) +
      " " +
      baseY.toFixed(2) +
      " L " +
      curPts[0].x.toFixed(2) +
      " " +
      curPts[0].y.toFixed(2) +
      " " +
      curveTail +
      " L " +
      curPts[curPts.length - 1].x.toFixed(2) +
      " " +
      baseY.toFixed(2) +
      " Z";

    var gridYTop = padT,
      gridYMid = padT + plotH / 2,
      gridYBase = baseY;
    var gridLinesHtml =
      '<line x1="' +
      padL +
      '" y1="' +
      gridYTop.toFixed(1) +
      '" x2="' +
      (padL + plotW).toFixed(1) +
      '" y2="' +
      gridYTop.toFixed(1) +
      '" class="chart-grid"></line>' +
      '<line x1="' +
      padL +
      '" y1="' +
      gridYMid.toFixed(1) +
      '" x2="' +
      (padL + plotW).toFixed(1) +
      '" y2="' +
      gridYMid.toFixed(1) +
      '" class="chart-grid"></line>' +
      '<line x1="' +
      padL +
      '" y1="' +
      gridYBase.toFixed(1) +
      '" x2="' +
      (padL + plotW).toFixed(1) +
      '" y2="' +
      gridYBase.toFixed(1) +
      '" class="chart-grid chart-grid-base"></line>';

    var dotsHtml = curPts
      .map(function (p) {
        return (
          '<circle cx="' +
          p.x.toFixed(2) +
          '" cy="' +
          p.y.toFixed(2) +
          '" r="4" class="chart-dot" data-view-month="' +
          p.m.key +
          '"><title>' +
          esc(p.m.label) +
          ": " +
          esc(fmtMoney(p.m.total)) +
          "</title></circle>"
        );
      })
      .join("");

    var chartId = "salesFill" + Math.random().toString(36).slice(2, 8);
    var svgHtml =
      '<svg class="shopify-chart-svg" viewBox="0 0 ' +
      vbW +
      " " +
      vbH +
      '" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">' +
      '<defs><linearGradient id="' +
      chartId +
      '" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0%" stop-color="var(--teal)" stop-opacity="0.30"></stop>' +
      '<stop offset="100%" stop-color="var(--teal)" stop-opacity="0"></stop>' +
      "</linearGradient></defs>" +
      gridLinesHtml +
      '<path d="' +
      curAreaD +
      '" fill="url(#' +
      chartId +
      ')" stroke="none"></path>' +
      (prevLineD ? '<path d="' + prevLineD + '" fill="none" class="chart-prev-line"></path>' : "") +
      '<path d="' +
      curLineD +
      '" fill="none" class="chart-cur-line"></path>' +
      dotsHtml +
      "</svg>";

    var yLabelsHtml =
      '<div class="chart-ylabel" style="top:0">' +
      shortMoney(niceMax) +
      "</div>" +
      '<div class="chart-ylabel" style="top:50%">' +
      shortMoney(niceMax / 2) +
      "</div>" +
      '<div class="chart-ylabel" style="top:100%">Rs. 0</div>';

    var xLabelsHtml = current
      .map(function (m) {
        return (
          '<div class="chart-xlabel" data-view-month="' +
          m.key +
          '">' +
          esc(m.label.split(" ")[0]) +
          "</div>"
        );
      })
      .join("");

    var curRangeLabel = current[0].label + " – " + current[current.length - 1].label;
    var prevRangeLabel = hasComparison ? previous[0].label + " – " + previous[previous.length - 1].label : "";
    var legendHtml =
      '<div class="shopify-chart-legend">' +
      '<span class="legend-item"><span class="legend-swatch solid"></span>' +
      esc(curRangeLabel) +
      "</span>" +
      (hasComparison
        ? '<span class="legend-item"><span class="legend-swatch dotted"></span>' + esc(prevRangeLabel) + "</span>"
        : "") +
      "</div>";

    return (
      headHtml +
      '<div class="shopify-chart">' +
      '<div class="shopify-chart-plot">' +
      '<div class="chart-ylabels">' +
      yLabelsHtml +
      "</div>" +
      '<div class="chart-svg-wrap">' +
      svgHtml +
      "</div>" +
      "</div>" +
      '<div class="chart-xlabels">' +
      xLabelsHtml +
      "</div>" +
      "</div>" +
      legendHtml
    );
  }

  function renderEarnings() {
    var months = monthlyEarnings();

    var thisKey = new Date().toISOString().slice(0, 7);
    var thisMonth = months.find(function (m) {
      return m.key === thisKey;
    });
    var bestMonth = months.reduce(function (best, m) {
      return !best || m.total > best.total ? m : best;
    }, null);
    var avgMonthly = months.length
      ? months.reduce(function (s, m) {
          return s + m.total;
        }, 0) / months.length
      : 0;

    var salesCardHtml = months.length
      ? shopifySalesCardHtml(months, "Total Sales")
      : '<div class="empty"><div class="glyph">📈</div><h3>No earnings yet</h3><p>Save an invoice to start tracking monthly earnings.</p></div>';

    var rowsHtml = months
      .slice()
      .reverse()
      .map(function (m) {
        return (
          '<tr class="row-clickable" data-view-month="' +
          m.key +
          '" title="Click to see this month\u2019s invoices">' +
          '<td class="item-name">' +
          esc(m.label) +
          "</td>" +
          '<td class="muted">' +
          m.count +
          " invoice" +
          (m.count === 1 ? "" : "s") +
          "</td>" +
          '<td class="num">' +
          fmtMoney(m.total) +
          "</td>" +
          "<td>" +
          changePillHtml(m) +
          "</td>" +
          '<td style="text-align:right;"><button class="btn btn-ghost" data-view-month-btn="' +
          m.key +
          '" style="padding:6px 12px;font-size:12px;">View Invoices</button></td>' +
          "</tr>"
        );
      })
      .join("");

    var rangeFrom = state.earningsRangeFrom || "";
    var rangeTo = state.earningsRangeTo || "";
    var rangeResultHtml = "";
    if (rangeFrom || rangeTo) {
      var rangeMatch = state.invoices.filter(function (inv) {
        if (!inv.date) return false;
        if (rangeFrom && inv.date < rangeFrom) return false;
        if (rangeTo && inv.date > rangeTo) return false;
        return true;
      });
      var rangeTotal = rangeMatch.reduce(function (s, i) {
        return s + i.total;
      }, 0);
      rangeResultHtml =
        '<div class="totals-box" style="margin-top:14px;"><div class="row" style="flex-direction:column; align-items:flex-end; gap:6px;">' +
        '<div style="display:flex; gap:26px; align-items:baseline;"><span class="lbl">Invoices in range</span><span class="muted num">' +
        rangeMatch.length +
        "</span></div>" +
        '<div style="display:flex; gap:26px; align-items:baseline;"><span class="lbl">Total Earned</span><span class="amt">' +
        fmtMoney(rangeTotal) +
        "</span></div>" +
        "</div></div>" +
        (rangeMatch.length
          ? '<div style="text-align:right;margin-top:10px;"><button class="btn btn-ghost" data-view-range>View These Invoices</button></div>'
          : "");
    } else {
      rangeResultHtml =
        '<p class="muted" style="margin-top:12px;">Pick a start date and/or end date to see exactly how much you earned in that period.</p>';
    }

    return (
      '<div class="page-head">' +
      "<div><h1>Monthly Earnings</h1><p>Track how much you're earning each month, and whether it's trending up or down.</p></div>" +
      "</div>" +
      beadsDivider() +
      '<div class="grid stat-grid">' +
      '<div class="stat"><div class="label">This Month</div><div class="value teal">' +
      fmtMoney(thisMonth ? thisMonth.total : 0) +
      "</div></div>" +
      '<div class="stat"><div class="label">Change vs Last Month</div><div class="value">' +
      changePillHtml(thisMonth) +
      "</div></div>" +
      '<div class="stat"><div class="label">Best Month</div><div class="value">' +
      (bestMonth ? esc(bestMonth.label) : "—") +
      "</div></div>" +
      '<div class="stat"><div class="label">Average / Month</div><div class="value teal">' +
      fmtMoney(avgMonthly) +
      "</div></div>" +
      "</div>" +
      '<div class="card" style="margin-top:20px;">' +
      '<h3 class="display" style="margin:0 0 6px;font-size:16px;">Pick Your Own Dates</h3>' +
      '<p class="field-hint" style="margin:0 0 14px;">Choose exactly which day to start counting from and which day to stop.</p>' +
      '<div class="field-row">' +
      '<div class="field"><label>From</label><div class="icon-field">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg>' +
      '<input type="date" data-earnings-range="from" value="' +
      esc(rangeFrom) +
      '"></div></div>' +
      '<div class="field"><label>To</label><div class="icon-field">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg>' +
      '<input type="date" data-earnings-range="to" value="' +
      esc(rangeTo) +
      '"></div></div>' +
      "</div>" +
      rangeResultHtml +
      "</div>" +
      '<div class="card shopify-sales-card" style="margin-top:20px;">' +
      salesCardHtml +
      "</div>" +
      '<div class="card" style="margin-top:20px;">' +
      '<h3 class="display" style="margin:0 0 14px;font-size:16px;">Month by Month</h3>' +
      '<p class="field-hint" style="margin:0 0 10px;">Click any month to see exactly which invoices made it up.</p>' +
      (months.length
        ? '<div class="table-wrap"><table><thead><tr><th>Month</th><th>Invoices</th><th class="num">Earnings</th><th>Trend</th><th></th></tr></thead><tbody>' +
          rowsHtml +
          "</tbody></table></div>"
        : '<p class="muted">No invoices saved yet.</p>') +
      "</div>"
    );
  }

  function renderInvoicesList() {
    var list = state.invoices;
    var filterChip = "";
    if (state.clientFilter) {
      list = list.filter(function (inv) {
        return inv.clientName === state.clientFilter;
      });
      filterChip =
        '<div class="filter-chip">Showing invoices for ' +
        esc(state.clientFilter) +
        " <button data-clear-filter>✕</button></div>";
    } else if (state.monthFilter) {
      list = list.filter(function (inv) {
        return (inv.date || "").slice(0, 7) === state.monthFilter;
      });
      var mLabel = new Date(
        state.monthFilter + "-01T00:00:00",
      ).toLocaleDateString("en-IN", { month: "long", year: "numeric" });
      filterChip =
        '<div class="filter-chip">Showing invoices for ' +
        esc(mLabel) +
        " <button data-clear-filter>✕</button></div>";
    } else if (
      state.rangeFilter &&
      (state.rangeFilter.from || state.rangeFilter.to)
    ) {
      var rf = state.rangeFilter;
      list = list.filter(function (inv) {
        if (!inv.date) return false;
        if (rf.from && inv.date < rf.from) return false;
        if (rf.to && inv.date > rf.to) return false;
        return true;
      });
      filterChip =
        '<div class="filter-chip">Showing invoices ' +
        (rf.from ? "from " + esc(fmtDate(rf.from)) + " " : "") +
        (rf.to ? "to " + esc(fmtDate(rf.to)) : "") +
        " <button data-clear-filter>✕</button></div>";
    }

    var rows = list
      .map(function (inv) {
        return (
          "<tr>" +
          '<td class="item-name">' +
          esc(inv.invoiceNo) +
          "</td>" +
          "<td>" +
          esc(inv.clientName) +
          '<div class="muted">' +
          esc(inv.phone || "") +
          "</div></td>" +
          "<td>" +
          fmtDate(inv.date) +
          "</td>" +
          "<td>" +
          inv.lines.length +
          " item(s)</td>" +
          '<td class="num">' +
          fmtMoney(inv.total) +
          "</td>" +
          '<td style="text-align:right; white-space:nowrap;">' +
          '<button class="btn btn-ghost" data-view-invoice="' +
          inv.id +
          '" style="padding:6px 12px;font-size:12px;">View</button> ' +
          '<button class="btn btn-ghost" data-edit-invoice="' +
          inv.id +
          '" style="padding:6px 12px;font-size:12px;">Edit</button> ' +
          '<button class="btn btn-danger" data-del-invoice="' +
          inv.id +
          '" style="padding:6px 12px;font-size:12px;">Delete</button>' +
          "</td>" +
          "</tr>"
        );
      })
      .join("");

    return (
      '<div class="page-head">' +
      "<div><h1>Invoice History</h1><p>Every invoice billed to your clients.</p></div>" +
      '<button class="btn btn-primary" data-nav="new-invoice">+ New Invoice</button>' +
      "</div>" +
      beadsDivider() +
      filterChip +
      '<div class="card">' +
      (list.length
        ? '<div class="table-wrap"><table><thead><tr><th>Invoice No.</th><th>Client</th><th>Date</th><th>Items</th><th>Total</th><th></th></tr></thead><tbody>' +
          rows +
          "</tbody></table></div>"
        : '<div class="empty"><div class="glyph">🧾</div><h3>No invoices yet</h3><p>Billed invoices will appear here.</p></div>') +
      "</div>"
    );
  }

  function renderClients() {
    var map = {};
    state.invoices.forEach(function (inv) {
      var key = inv.clientName.trim().toLowerCase();
      if (!map[key]) {
        map[key] = {
          name: inv.clientName,
          phone: inv.phone,
          address: inv.address,
          qty: 0,
          total: 0,
          invoices: 0,
          lastDate: inv.date,
        };
      }
      var c = map[key];
      c.qty += inv.lines.reduce(function (s, l) {
        return s + l.qty;
      }, 0);
      c.total += inv.total;
      c.invoices += 1;
      if (inv.phone && !c.phone) c.phone = inv.phone;
      if (inv.date > c.lastDate) {
        c.lastDate = inv.date;
      }
    });
    var clients = Object.keys(map)
      .map(function (k) {
        return map[k];
      })
      .sort(function (a, b) {
        return b.total - a.total;
      });

    var query = (state.clientSearchQuery || "").trim().toLowerCase();
    var filteredClients = query
      ? clients.filter(function (c) {
          var words = c.name.toLowerCase().split(/\s+/);
          return (
            c.name.toLowerCase().indexOf(query) > -1 ||
            (c.phone || "").toLowerCase().indexOf(query) > -1 ||
            words.some(function (w) {
              return w.indexOf(query) === 0;
            })
          );
        })
      : clients;

    var rows = filteredClients
      .map(function (c) {
        return (
          "<tr>" +
          '<td class="item-name" style="display:flex;align-items:center;gap:10px;">' +
          thumbHTML({ name: c.name }, 34) +
          " <div>" +
          esc(c.name) +
          '<div class="muted">' +
          esc(c.phone || "") +
          "</div></div></td>" +
          "<td>" +
          c.invoices +
          "</td>" +
          "<td>" +
          c.qty +
          " units</td>" +
          '<td class="num">' +
          fmtMoney(c.total) +
          "</td>" +
          "<td>" +
          fmtDate(c.lastDate) +
          "</td>" +
          '<td style="text-align:right;"><button class="btn btn-ghost" data-view-client="' +
          esc(c.name) +
          '" style="padding:6px 12px;font-size:12px;">View Invoices</button></td>' +
          "</tr>"
        );
      })
      .join("");

    var emptyState = clients.length
      ? '<div class="empty"><div class="glyph">🔎</div><h3>No matches</h3><p>No clients match "' +
        esc(state.clientSearchQuery) +
        '".</p></div>'
      : '<div class="empty"><div class="glyph">🧑‍🤝‍🧑</div><h3>No clients yet</h3><p>Clients appear here automatically once you save an invoice.</p></div>';

    return (
      '<div class="page-head">' +
      "<div><h1>Clients</h1><p>Everyone you have billed, with total quantity and spend.</p></div>" +
      '<div class="btn-row">' +
      '<div class="icon-field" style="width:230px;">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>' +
      '<input type="text" data-client-search value="' +
      esc(state.clientSearchQuery || "") +
      '" placeholder="Search clients…">' +
      "</div>" +
      "</div>" +
      "</div>" +
      beadsDivider() +
      '<div class="card">' +
      (filteredClients.length
        ? '<div class="table-wrap"><table><thead><tr><th>Client</th><th>Invoices</th><th>Total Quantity</th><th>Total Spent</th><th>Last Billed</th><th></th></tr></thead><tbody>' +
          rows +
          "</tbody></table></div>"
        : emptyState) +
      "</div>"
    );
  }

  function renderItemOrders() {
    var item = state.items.find(function (i) {
      return i.id === state.activeItemId;
    });
    if (!item) {
      return '<div class="empty"><div class="glyph">📦</div><h3>Item not found</h3></div>';
    }

    var byClient = {};
    state.invoices.forEach(function (inv) {
      inv.lines.forEach(function (l) {
        if (l.itemId !== item.id) return;
        var key = inv.clientName.trim().toLowerCase();
        if (!byClient[key]) {
          byClient[key] = { name: inv.clientName, qty: 0, total: 0, orders: 0 };
        }
        byClient[key].qty += l.qty;
        byClient[key].total += l.amount;
        byClient[key].orders += 1;
      });
    });
    var clients = Object.keys(byClient)
      .map(function (k) {
        return byClient[k];
      })
      .sort(function (a, b) {
        return b.total - a.total;
      });
    var grandTotal = clients.reduce(function (s, c) {
      return s + c.total;
    }, 0);
    var grandQty = clients.reduce(function (s, c) {
      return s + c.qty;
    }, 0);

    var rows = clients
      .map(function (c) {
        return (
          "<tr>" +
          '<td class="item-name" style="display:flex;align-items:center;gap:10px;">' +
          thumbHTML({ name: c.name }, 32) +
          " " +
          esc(c.name) +
          "</td>" +
          "<td>" +
          c.qty +
          " " +
          unitLabel(item.unit) +
          "</td>" +
          '<td class="num">' +
          fmtMoney(c.total) +
          "</td>" +
          "</tr>"
        );
      })
      .join("");

    return (
      '<div class="page-head no-print">' +
      "<div><h1>Item Orders</h1><p>Everyone who has ordered " +
      esc(item.name) +
      ", and how much.</p></div>" +
      '<div class="btn-row">' +
      '<button class="btn btn-ghost" data-nav="items">Back to Inventory</button>' +
      '<button class="btn btn-gold" data-print>Print / Save PDF</button>' +
      '<button class="btn btn-primary" data-new-order-item="' +
      item.id +
      '">+ New Order for ' +
      esc(item.name) +
      "</button>" +
      "</div>" +
      "</div>" +
      '<div class="invoice-sheet">' +
      '<div class="inv-top">' +
      '<div style="display:flex;align-items:center;gap:8px;"><img src="logo-mark.png" alt="JSK Creation" class="inv-brand-mark"></div>' +
      "</div>" +
      '<div class="inv-client" style="display:flex; align-items:center; gap:14px; margin-top:22px;">' +
      thumbHTML(item, 56) +
      "<div>" +
      '<h2 style="margin:0;">' +
      esc(item.name) +
      "</h2>" +
      '<div class="sub">' +
      item.qty +
      " " +
      unitLabel(item.unit) +
      " in stock &middot; " +
      fmtMoney(item.price) +
      " per " +
      unitLabel(item.unit) +
      "</div>" +
      "</div>" +
      "</div>" +
      beadsDivider() +
      (clients.length
        ? '<div class="inv-items"><div class="table-wrap">' +
          "<table><thead><tr><th>Clients</th><th>Quantity</th><th>Total Price</th></tr></thead><tbody>" +
          rows +
          "</tbody></table>" +
          "</div></div>" +
          '<div class="totals-box"><div class="row"><span class="lbl">Total Price</span><span class="amt">' +
          fmtMoney(grandTotal) +
          "</span></div></div>" +
          '<p class="muted" style="margin-top:6px;">' +
          grandQty +
          " " +
          unitLabel(item.unit) +
          " ordered in total across " +
          clients.length +
          " client(s).</p>"
        : '<div class="empty"><div class="glyph">🧾</div><h3>No orders yet</h3><p>Once this item appears on a saved invoice, buyers will be listed here.</p></div>') +
      invoiceFooterHTML() +
      "</div>"
    );
  }

  function renderBulkInvoice() {
    if (!state.bulkDraft) startBulkInvoice();
    var d = state.bulkDraft;
    var item = bulkItem();

    var itemOptions =
      '<option value="">Select an item…</option>' +
      state.items
        .map(function (i) {
          return (
            '<option value="' +
            i.id +
            '"' +
            (i.id === d.itemId ? " selected" : "") +
            ">" +
            esc(i.name) +
            " (" +
            i.qty +
            " " +
            unitLabel(i.unit) +
            " left)</option>"
          );
        })
        .join("");

    var rowsHtml = d.rows
      .map(function (r) {
        var amount = bulkRowAmount(r);
        return (
          '<div class="line-item-row" style="grid-template-columns:2fr 100px 110px 110px 34px;">' +
          '<input type="text" data-bulk-row="' +
          r.id +
          '" data-bulk-field="name" value="' +
          esc(r.name) +
          '" placeholder="Client name">' +
          '<input type="number" min="0" step="1" value="' +
          r.qty +
          '" data-bulk-row="' +
          r.id +
          '" data-bulk-field="qty">' +
          '<div class="muted" style="text-align:right;">' +
          (item ? fmtMoney(item.price) + "/" + unitLabel(item.unit) : "—") +
          "</div>" +
          '<div class="amt">' +
          fmtMoney(amount) +
          "</div>" +
          '<button class="remove-row" data-remove-bulk-row="' +
          r.id +
          '" title="Remove">✕</button>' +
          "</div>"
        );
      })
      .join("");

    var errs = state.formErrors;
    var errHtml =
      errs && errs.length
        ? '<div style="background:#FBEEEA;border:1px solid #EAD3CC;color:var(--danger);padding:12px 14px;border-radius:8px;font-size:13px;margin-bottom:16px;">' +
          errs.map(esc).join("<br>") +
          "</div>"
        : "";

    var isEdit = !!state.editingBatchId;
    return (
      '<div class="page-head">' +
      "<div><h1>" +
      (isEdit ? "Edit Multi-Client Order" : "New Multi-Client Order") +
      "</h1><p>" +
      (isEdit
        ? "Adjust clients or quantities on this combined order — you can add, remove, or update any row."
        : "One item, many clients — enter each client's quantity and generate one combined report.") +
      "</p></div>" +
      '<div class="btn-row">' +
      '<button class="btn btn-ghost" data-cancel-bulk>Cancel</button>' +
      '<button class="btn btn-primary" data-save-bulk>' +
      (isEdit ? "Save Changes" : "Save &amp; View Report") +
      "</button>" +
      "</div>" +
      "</div>" +
      beadsDivider() +
      errHtml +
      '<div class="card">' +
      '<h3 class="display" style="margin:0 0 14px;font-size:16px;">Item</h3>' +
      '<div class="field"><label>Choose the item being ordered</label>' +
      '<select data-bulk-item style="width:100%;padding:10px 12px;border-radius:8px;border:1px solid var(--line);font-size:14px;">' +
      itemOptions +
      "</select></div>" +
      (item
        ? '<p class="muted" style="margin-top:6px;">' +
          item.qty +
          " " +
          unitLabel(item.unit) +
          " in stock &middot; " +
          fmtMoney(item.price) +
          " per " +
          unitLabel(item.unit) +
          "</p>"
        : "") +
      "</div>" +
      '<div class="card" style="margin-top:20px;">' +
      '<h3 class="display" style="margin:0 0 14px;font-size:16px;">Clients</h3>' +
      (state.items.length
        ? '<div class="line-item-row muted" style="grid-template-columns:2fr 100px 110px 110px 34px;font-size:11px;text-transform:uppercase;letter-spacing:0.06em;"><div>Client Name</div><div>Qty</div><div style="text-align:right;">Price</div><div style="text-align:right;">Amount</div><div></div></div>' +
          rowsHtml +
          '<button class="add-row-btn" data-add-bulk-row>+ Add another client</button>'
        : '<div class="empty"><div class="glyph">📦</div><h3>No items in inventory</h3></div>') +
      '<div class="totals-box"><div class="row" style="flex-direction:column; align-items:flex-end; gap:6px;">' +
      '<div style="display:flex; gap:26px; align-items:baseline;"><span class="lbl">Total Quantity</span><span class="muted num">' +
      bulkGrandQty() +
      (item ? " " + unitLabel(item.unit) : "") +
      "</span></div>" +
      '<div style="display:flex; gap:26px; align-items:baseline;"><span class="lbl">Total Price</span><span class="amt num">' +
      fmtMoney(bulkGrandTotal()) +
      "</span></div>" +
      "</div></div>" +
      "</div>"
    );
  }

  function renderBulkOrdersList() {
    var batches = getBulkBatches();
    var rows = batches
      .map(function (b) {
        return (
          "<tr>" +
          "<td>" +
          fmtDate(b.date) +
          "</td>" +
          '<td class="item-name" style="display:flex;align-items:center;gap:10px;">' +
          thumbHTML({ name: b.itemName }, 32) +
          " " +
          esc(b.itemName) +
          "</td>" +
          "<td>" +
          b.clients +
          (b.clients === 1 ? " client" : " clients") +
          "</td>" +
          "<td>" +
          b.totalQty +
          "</td>" +
          '<td class="num">' +
          fmtMoney(b.totalAmount) +
          "</td>" +
          '<td style="text-align:right; white-space:nowrap;">' +
          '<button class="btn btn-ghost" data-view-bulk-batch="' +
          b.id +
          '" style="padding:6px 12px;font-size:12px;">View</button> ' +
          '<button class="btn btn-ghost" data-edit-bulk-batch="' +
          b.id +
          '" style="padding:6px 12px;font-size:12px;">Edit</button> ' +
          '<button class="btn btn-danger" data-del-bulk-batch="' +
          b.id +
          '" style="padding:6px 12px;font-size:12px;">Delete</button>' +
          "</td>" +
          "</tr>"
        );
      })
      .join("");

    var emptyState =
      '<div class="empty"><div class="glyph">🧾</div><h3>No multi-client orders yet</h3><p>Use "+ Multi-Client Order" to bill one item to several clients at once — every one you save shows up here so you can view or edit it anytime.</p></div>';

    return (
      '<div class="page-head">' +
      "<div><h1>Multi-Client Orders</h1><p>Every combined order you've saved — one item, several clients. Open any of them to view or edit it.</p></div>" +
      '<div class="btn-row">' +
      '<button class="btn btn-gold" data-new-bulk-invoice>+ Multi-Client Order</button>' +
      "</div>" +
      "</div>" +
      beadsDivider() +
      '<div class="card">' +
      (batches.length
        ? '<div class="table-wrap"><table><thead><tr><th>Date</th><th>Item</th><th>Clients</th><th>Total Qty</th><th>Total Amount</th><th></th></tr></thead><tbody>' +
          rows +
          "</tbody></table></div>"
        : emptyState) +
      "</div>"
    );
  }

  function renderBulkOrderView() {
    var batchId = state.activeBatchId;
    var invs = state.invoices.filter(function (i) {
      return i.batchId === batchId;
    });
    if (!invs.length) {
      return (
        '<div class="page-head no-print">' +
        "<div><h1>Multi-Client Order</h1></div>" +
        '<div class="btn-row">' +
        '<button class="btn btn-ghost" data-nav="bulk-orders">Back to Multi-Client Orders</button>' +
        "</div>" +
        "</div>" +
        '<div class="empty"><div class="glyph">🧾</div><h3>Order not found</h3><p>This multi-client order may have already been deleted.</p></div>'
      );
    }
    var first = invs[0];
    var line0 = first.lines[0];
    var item = state.items.find(function (i) {
      return i.id === line0.itemId;
    });

    var rows = invs
      .map(function (inv) {
        var l = inv.lines[0];
        return (
          "<tr>" +
          '<td class="item-name" style="display:flex;align-items:center;gap:10px;">' +
          thumbHTML({ name: inv.clientName }, 32) +
          " " +
          esc(inv.clientName) +
          "</td>" +
          "<td>" +
          l.qty +
          " " +
          unitLabel(l.unit) +
          "</td>" +
          '<td class="num">' +
          fmtMoney(l.amount) +
          "</td>" +
          "</tr>"
        );
      })
      .join("");

    var totalQty = invs.reduce(function (s, inv) {
      return s + (inv.lines[0] ? inv.lines[0].qty : 0);
    }, 0);
    var totalAmount = invs.reduce(function (s, inv) {
      return s + inv.total;
    }, 0);
    var displayItem = item || { name: line0.name || "Item" };

    return (
      '<div class="page-head no-print">' +
      "<div><h1>Multi-Client Order</h1><p>" +
      esc(displayItem.name) +
      " &middot; " +
      fmtDate(first.date) +
      "</p></div>" +
      '<div class="btn-row">' +
      '<button class="btn btn-ghost" data-nav="bulk-orders">Back to Multi-Client Orders</button>' +
      '<button class="btn btn-gold" data-print>Print / Save PDF</button>' +
      '<button class="btn btn-primary" data-edit-bulk-batch="' +
      batchId +
      '">Edit This Order</button>' +
      "</div>" +
      "</div>" +
      '<div class="invoice-sheet">' +
      '<div class="inv-top">' +
      '<div style="display:flex;align-items:center;gap:8px;"><img src="logo-mark.png" alt="JSK Creation" class="inv-brand-mark"></div>' +
      "</div>" +
      '<div class="inv-client" style="display:flex; align-items:center; gap:14px; margin-top:22px;">' +
      thumbHTML(displayItem, 56) +
      "<div>" +
      '<h2 style="margin:0;">' +
      esc(displayItem.name) +
      "</h2>" +
      '<div class="sub">' +
      fmtDate(first.date) +
      " &middot; " +
      invs.length +
      (invs.length === 1 ? " client" : " clients") +
      "</div>" +
      "</div>" +
      "</div>" +
      beadsDivider() +
      '<div class="inv-items"><div class="table-wrap">' +
      "<table><thead><tr><th>Client</th><th>Quantity</th><th>Amount</th></tr></thead><tbody>" +
      rows +
      "</tbody></table>" +
      "</div></div>" +
      '<div class="totals-box"><div class="row" style="flex-direction:column; align-items:flex-end; gap:6px;">' +
      '<div style="display:flex; gap:26px; align-items:baseline;"><span class="lbl">Total Quantity</span><span class="muted num">' +
      totalQty +
      "</span></div>" +
      '<div style="display:flex; gap:26px; align-items:baseline;"><span class="lbl">Total Amount</span><span class="amt num">' +
      fmtMoney(totalAmount) +
      "</span></div>" +
      "</div></div>" +
      invoiceFooterHTML() +
      "</div>"
    );
  }

  function renderInvoiceView() {
    var inv = state.invoices.find(function (i) {
      return i.id === state.activeInvoiceId;
    });
    if (!inv) {
      return '<div class="empty"><div class="glyph">🧾</div><h3>Invoice not found</h3></div>';
    }
    var rows = inv.lines
      .map(function (l) {
        return (
          "<tr>" +
          '<td><div class="row-item">' +
          thumbHTML(l, 28) +
          " " +
          esc(l.name) +
          "</div></td>" +
          '<td class="qty">' +
          // a "pack" order (e.g. someone bought 2 packs of "3 Pc") stores
          // qty as the number of PACKS, not pieces — showing it against the
          // item's base stock unit ("2 pc") reads as only 2 pieces were
          // sold and contradicted the "(3 Pc)" already appended to the
          // item name, which is exactly what was confusing on the bill.
          // When a pack/variant label is present, show against that label
          // instead, e.g. "2 x 3 Pc".
          (l.variant
            ? l.qty + " x " + esc(l.variant)
            : l.qty + " " + unitLabel(l.unit)) +
          "</td>" +
          '<td class="amt">' +
          fmtMoney(l.price) +
          "</td>" +
          '<td class="amt">' +
          fmtMoney(l.amount) +
          "</td>" +
          "</tr>"
        );
      })
      .join("");

    return (
      '<div class="page-head no-print">' +
      "<div><h1>Invoice</h1><p>" +
      esc(inv.invoiceNo) +
      "</p></div>" +
      '<div class="btn-row">' +
      '<button class="btn btn-ghost" data-nav="invoices">Back to History</button>' +
      '<button class="btn btn-ghost" data-edit-invoice="' +
      inv.id +
      '">Edit Invoice</button>' +
      '<button class="btn btn-gold" data-print>Print / Save PDF</button>' +
      "</div>" +
      "</div>" +
      '<div class="invoice-sheet">' +
      '<div class="inv-top">' +
      '<div style="display:flex;align-items:center;gap:8px;"><img src="logo-mark.png" alt="JSK Creation" class="inv-brand-mark"></div>' +
      '<div class="inv-meta">Invoice No.<br><span class="num">' +
      esc(inv.invoiceNo) +
      "</span><br>Date: " +
      fmtDate(inv.date) +
      "</div>" +
      "</div>" +
      beadsDivider() +
      '<div class="inv-client">' +
      "<h2>" +
      esc(inv.clientName) +
      "</h2>" +
      '<div class="sub">' +
      esc(inv.phone || "") +
      (inv.phone && inv.address ? " · " : "") +
      esc(inv.address || "") +
      "</div>" +
      "</div>" +
      '<div class="inv-items table-wrap">' +
      '<table><thead><tr><th>Item</th><th class="qty">Quantity</th><th class="amt">Price</th><th class="amt">Amount</th></tr></thead><tbody>' +
      rows +
      "</tbody></table>" +
      "</div>" +
      '<div class="totals-box"><div class="row" style="flex-direction:column; align-items:flex-end; gap:6px;">' +
      (inv.deliveryCharges
        ? '<div style="display:flex; gap:26px; align-items:baseline;"><span class="lbl">Items Subtotal</span><span class="muted num">' +
          fmtMoney(
            inv.subtotal != null
              ? inv.subtotal
              : inv.total - inv.deliveryCharges,
          ) +
          "</span></div>" +
          '<div style="display:flex; gap:26px; align-items:baseline;"><span class="lbl">Delivery Charges</span><span class="muted num">' +
          fmtMoney(inv.deliveryCharges) +
          "</span></div>"
        : "") +
      '<div style="display:flex; gap:26px; align-items:baseline;"><span class="lbl">Total Price</span><span class="amt">' +
      fmtMoney(inv.total) +
      "</span></div>" +
      "</div></div>" +
      invoiceFooterHTML() +
      "</div>"
    );
  }

  /* ================= modal ================= */
  function renderModal() {
    if (!state.modal) return "";
    if (state.modal.type === "item") {
      var it = state.modal.payload;
      var isEdit = !!it.id;
      return (
        '<div class="modal-backdrop" data-close-modal>' +
        '<div class="modal" onclick="event.stopPropagation()">' +
        "<h2>" +
        (isEdit ? "Edit Item" : "Add Item") +
        "</h2>" +
        '<p class="muted" style="margin-top:0;">Track it in your inventory so it can be billed on invoices — and shown live on the website.</p>' +
        '<form id="item-form">' +
        '<div class="field"><label>Item Name</label><input name="name" type="text" value="' +
        esc(it.name) +
        '" placeholder="e.g. Kundan" required></div>' +
        '<div class="field-row">' +
        '<div class="field"><label>Quantity We Have</label><input name="qty" type="number" min="0" step="1" value="' +
        it.qty +
        '"></div>' +
        '<div class="field"><label>Unit</label><select name="unit">' +
        '<option value="pc" ' +
        ((it.unit || "pc") === "pc" ? "selected" : "") +
        ">Per pc</option>" +
        '<option value="pair" ' +
        (it.unit === "pair" ? "selected" : "") +
        ">Per pair</option>" +
        '<option value="packet" ' +
        (it.unit === "packet" ? "selected" : "") +
        ">Per packet</option>" +
        '<option value="yard" ' +
        (it.unit === "yard" ? "selected" : "") +
        ">Per yard</option>" +
        '<option value="gram" ' +
        (it.unit === "gram" ? "selected" : "") +
        ">Per gram</option>" +
        "</select></div>" +
        "</div>" +
        '<div class="field"><label>Price</label><div class="prefix-input"><span class="prefix-tag">Rs.</span><input name="price" type="number" min="0" step="1" value="' +
        it.price +
        '"></div></div>' +
        '<div class="field"><label>Website Category</label><select name="cat">' +
        orderedCategories()
          .map(function (entry) {
            var c = entry.cat;
            var isSel =
              (it.cat || (state.categories[0] && state.categories[0].id)) ===
              c.id;
            return (
              '<option value="' +
              esc(c.id) +
              '" ' +
              (isSel ? "selected" : "") +
              ">" +
              (entry.depth ? "\u2003↳ " : "") +
              esc(c.label) +
              "</option>"
            );
          })
          .join("") +
        "</select>" +
        '<p class="field-hint">Manage the category list itself, and its sub-categories, from the Categories tab.</p>' +
        "</div>" +
        '<div class="field"><label>Listing</label><select name="listing">' +
        '<option value="catalog" ' +
        ((it.listing || "catalog") === "catalog" ? "selected" : "") +
        ">Catalog (normal, in-stock item)</option>" +
        '<option value="prebook" ' +
        (it.listing === "prebook" ? "selected" : "") +
        ">Pre-Booking (ships in 2–4 weeks)</option>" +
        "</select>" +
        '<p class="field-hint">Pre-Booking items appear only in the website\'s Pre-Booking section, not the main catalog — switch this back to Catalog once new stock has actually arrived.</p>' +
        "</div>" +
        '<div class="field field-checkbox">' +
        '<label style="display:flex;align-items:center;gap:8px;text-transform:none;font-weight:600;">' +
        '<input type="checkbox" name="trending" value="1" ' +
        (it.trending ? "checked" : "") +
        ' style="width:auto;"> ⭐ Feature in Trending / New Arrivals section' +
        "</label>" +
        '<p class="field-hint">Pins this item near the top of the website\'s home-page Trending row, ahead of everything else.</p>' +
        "</div>" +
        '<div class="field variant-options-field">' +
        '<label>Pack Size Options <em style="text-transform:none;font-weight:400;color:#9A8C7C;">(optional — e.g. 1 Pc, 3 Pc, 6 Pc, each with its own price)</em></label>' +
        '<div class="opt-rows" id="packOptRows">' + optionRowsHtml(it.packOptions, "pack", "e.g. 3 Pc") + "</div>" +
        '<button type="button" class="btn btn-ghost opt-add-btn" data-add-opt-row="pack">+ Add Pack Size</button>' +
        '<p class="field-hint">Leave empty if this item is sold at one fixed price with no pack choices. If you add these, the Price field above is used as the base/first pack price.</p>' +
        "</div>" +
        '<div class="field variant-options-field">' +
        '<label>Stone / Item Size Options <em style="text-transform:none;font-weight:400;color:#9A8C7C;">(optional — e.g. 4mm, 6mm, 8mm)</em></label>' +
        '<div class="opt-rows" id="sizeOptRows">' + optionRowsHtml(it.sizeOptions, "size", "e.g. 6mm") + "</div>" +
        '<button type="button" class="btn btn-ghost opt-add-btn" data-add-opt-row="size">+ Add Size</button>' +
        "</div>" +
        '<div class="field variant-options-field">' +
        '<label>Colour Options <em style="text-transform:none;font-weight:400;color:#9A8C7C;">(optional — e.g. Red, Gold, Green)</em></label>' +
        '<div class="opt-rows" id="colorOptRows">' + colorRowsHtml(it.colorOptions) + "</div>" +
        '<button type="button" class="btn btn-ghost opt-add-btn" data-add-opt-row="color">+ Add Colour</button>' +
        "</div>" +
        '<div class="field"><label>Website Description <em style="text-transform:none;font-weight:400;color:#9A8C7C;">(optional)</em></label><input name="desc" type="text" value="' +
        esc(it.desc || "") +
        '" placeholder="Shown on the product card on the website"></div>' +
        '<div class="field">' +
        "<label>Item Photos <em style=\"text-transform:none;font-weight:400;color:#9A8C7C;\">(up to 4, optional)</em></label>" +
        '<div class="img-upload-grid">' +
        [1, 2, 3, 4]
          .map(function (n) {
            var val = (it.images && it.images[n - 1]) || (n === 1 ? it.img : "") || "";
            return (
              '<div class="img-upload-slot">' +
              '<div class="img-upload-preview' +
              (val ? " has-img" : "") +
              '" id="imgPreview' + n + '">' +
              (val
                ? '<img src="' + esc(val) + '" alt="Preview ' + n + '">'
                : '<span class="img-upload-placeholder">Photo ' + n + "</span>") +
              "</div>" +
              '<div class="img-upload-actions">' +
              '<label class="btn btn-ghost img-browse-btn" for="imgFileInput' + n + '">' + (val ? "Change" : "Browse") + "</label>" +
              '<input type="file" id="imgFileInput' + n + '" accept="image/*" hidden>' +
              '<button type="button" class="btn btn-ghost" id="imgClearBtn' + n + '"' +
              (val ? "" : " hidden") +
              ">Remove</button>" +
              "</div>" +
              '<input type="hidden" name="img' + n + '" id="imgHidden' + n + '" value="' + esc(val) + '">' +
              "</div>"
            );
          })
          .join("") +
        "</div>" +
        '<p class="field-hint" id="imgUploadHint">Choose up to 4 photos from your phone or computer (JPG, PNG, WebP). The first photo is the main one shown on the catalog card; all 4 appear in the website\'s product gallery. Leave empty to use an automatic monogram badge. Quantity 0 just shows "Out of Stock" on the catalog card — use the Listing option above to move it into Pre-Booking.</p>' +
        "</div>" +
        '<div class="modal-actions">' +
        '<button type="button" class="btn btn-ghost" data-close-modal>Cancel</button>' +
        '<button type="submit" class="btn btn-primary" id="itemFormSubmit">' +
        (isEdit ? "Save Changes" : "Add Item") +
        "</button>" +
        "</div>" +
        "</form>" +
        "</div>" +
        "</div>"
      );
    }
    if (state.modal.type === "confirmDeleteItem") {
      var item = state.items.find(function (i) {
        return i.id === state.modal.payload.id;
      });
      return (
        '<div class="modal-backdrop" data-close-modal>' +
        '<div class="modal" onclick="event.stopPropagation()">' +
        "<h2>Delete Item?</h2>" +
        '<p class="muted">This removes "' +
        esc(item ? item.name : "") +
        '" from inventory and the website. Past invoices are not affected.</p>' +
        '<div class="modal-actions">' +
        '<button class="btn btn-ghost" data-close-modal>Cancel</button>' +
        '<button class="btn btn-danger" style="background:var(--danger);color:#fff;border:none;" data-confirm-del-item="' +
        state.modal.payload.id +
        '">Delete</button>' +
        "</div>" +
        "</div>" +
        "</div>"
      );
    }
    if (state.modal.type === "category") {
      var cPayload = state.modal.payload;
      var isCatEdit = !!cPayload.id;
      var hasChildren =
        isCatEdit && subCategoriesOf(cPayload.id).length > 0;
      var parentOptions = topLevelCategories().filter(function (c) {
        return c.id !== cPayload.id;
      });
      return (
        '<div class="modal-backdrop" data-close-modal>' +
        '<div class="modal" onclick="event.stopPropagation()">' +
        "<h2>" +
        (isCatEdit ? "Edit Category" : "Add Category") +
        "</h2>" +
        '<p class="muted" style="margin-top:0;">' +
        (isCatEdit
          ? "Renaming updates the label shown on the website immediately."
          : "This appears as a new category in the item form and on the website's Shop By Category menu.") +
        "</p>" +
        '<form id="category-form">' +
        '<div class="field"><label>Category Name</label><input name="label" type="text" value="' +
        esc(cPayload.label) +
        '" placeholder="e.g. Bridal Sets" required></div>' +
        (hasChildren
          ? '<p class="field-hint">This category already has its own sub-categories, so it can\'t be nested under another one.</p>'
          : '<div class="field"><label>Parent Category <em style="text-transform:none;font-weight:400;color:#9A8C7C;">(optional — pick one to make this a sub-category)</em></label><select name="parentId">' +
            '<option value="">None — top-level category</option>' +
            parentOptions
              .map(function (p) {
                return (
                  '<option value="' +
                  esc(p.id) +
                  '" ' +
                  (cPayload.parentId === p.id ? "selected" : "") +
                  ">" +
                  esc(p.label) +
                  "</option>"
                );
              })
              .join("") +
            "</select></div>") +
        '<div class="modal-actions">' +
        '<button type="button" class="btn btn-ghost" data-close-modal>Cancel</button>' +
        '<button type="submit" class="btn btn-primary">' +
        (isCatEdit ? "Save Changes" : "Add Category") +
        "</button>" +
        "</div>" +
        "</form>" +
        "</div>" +
        "</div>"
      );
    }
    if (state.modal.type === "confirmDeleteCategory") {
      var delCatId = state.modal.payload.id;
      var delCat = state.categories.find(function (c) {
        return c.id === delCatId;
      });
      var delItemCount = state.modal.payload.itemCount;
      var delChildCount = state.modal.payload.childCount;
      var otherCats = state.categories.filter(function (c) {
        return c.id !== delCatId;
      });
      var isOnlyCat = state.categories.length <= 1;
      var isBlocked = isOnlyCat || delChildCount > 0;
      return (
        '<div class="modal-backdrop" data-close-modal>' +
        '<div class="modal" onclick="event.stopPropagation()">' +
        "<h2>Delete Category?</h2>" +
        (isBlocked
          ? '<p class="muted">' +
            (delChildCount > 0
              ? '"' +
                esc(delCat ? delCat.label : "") +
                '" has ' +
                delChildCount +
                " sub-categor" +
                (delChildCount === 1 ? "y" : "ies") +
                " under it. Delete or move those first, then delete this one."
              : '"' +
                esc(delCat ? delCat.label : "") +
                '" is your only category. Add another category first before deleting this one.') +
            "</p>" +
            '<div class="modal-actions"><button class="btn btn-ghost" data-close-modal>Close</button></div>'
          : '<p class="muted">This removes "' +
            esc(delCat ? delCat.label : "") +
            '" from the item form and the website\'s category menu' +
            (delItemCount
              ? ". " +
                delItemCount +
                " item(s) are currently in this category — choose where to move them:"
              : ".") +
            "</p>" +
            (delItemCount
              ? '<div class="field"><label>Move items to</label><select id="catReassignSelect">' +
                otherCats
                  .map(function (c) {
                    return (
                      '<option value="' +
                      esc(c.id) +
                      '">' +
                      esc(c.label) +
                      "</option>"
                    );
                  })
                  .join("") +
                "</select></div>"
              : "") +
            '<div class="modal-actions">' +
            '<button class="btn btn-ghost" data-close-modal>Cancel</button>' +
            '<button class="btn btn-danger" style="background:var(--danger);color:#fff;border:none;" data-confirm-del-category="' +
            delCatId +
            '">Delete</button>' +
            "</div>") +
        "</div>" +
        "</div>"
      );
    }
    if (state.modal.type === "changePassword") {
      var cpError = state.modal.payload && state.modal.payload.error;
      return (
        '<div class="modal-backdrop" data-close-modal>' +
        '<div class="modal" onclick="event.stopPropagation()">' +
        "<h2>Change Warehouse Password</h2>" +
        '<p class="muted" style="margin-top:0;">Enter your current password and choose a new one.</p>' +
        '<form id="change-password-form">' +
        '<div class="field"><label>Current Password</label><input type="password" id="cpCurrent" autocomplete="current-password" required></div>' +
        '<div class="field"><label>New Password</label><input type="password" id="cpNew" autocomplete="new-password" required minlength="4"></div>' +
        '<div class="field"><label>Confirm New Password</label><input type="password" id="cpConfirm" autocomplete="new-password" required minlength="4"></div>' +
        (cpError ? '<p class="gate-error">' + esc(cpError) + "</p>" : "") +
        '<div class="modal-actions">' +
        '<button type="button" class="btn btn-ghost" data-close-modal>Cancel</button>' +
        '<button type="submit" class="btn btn-primary">Update Password</button>' +
        "</div>" +
        "</form>" +
        "</div>" +
        "</div>"
      );
    }
    if (state.modal.type === "confirmDeleteInvoice") {
      return (
        '<div class="modal-backdrop" data-close-modal>' +
        '<div class="modal" onclick="event.stopPropagation()">' +
        "<h2>Delete Invoice?</h2>" +
        '<p class="muted">This permanently removes the invoice from history.</p>' +
        '<div class="modal-actions">' +
        '<button class="btn btn-ghost" data-close-modal>Cancel</button>' +
        '<button class="btn btn-danger" style="background:var(--danger);color:#fff;border:none;" data-confirm-del-invoice="' +
        state.modal.payload.id +
        '">Delete</button>' +
        "</div>" +
        "</div>" +
        "</div>"
      );
    }
    if (state.modal.type === "confirmDeleteBulkBatch") {
      return (
        '<div class="modal-backdrop" data-close-modal>' +
        '<div class="modal" onclick="event.stopPropagation()">' +
        "<h2>Delete Multi-Client Order?</h2>" +
        '<p class="muted">This permanently removes every client invoice in this combined order and returns the stock.</p>' +
        '<div class="modal-actions">' +
        '<button class="btn btn-ghost" data-close-modal>Cancel</button>' +
        '<button class="btn btn-danger" style="background:var(--danger);color:#fff;border:none;" data-confirm-del-bulk-batch="' +
        state.modal.payload.id +
        '">Delete</button>' +
        "</div>" +
        "</div>" +
        "</div>"
      );
    }
    return "";
  }

  /* ================= root render ================= */
  function render() {
    var body = "";
    switch (state.view) {
      case "orders":
        body = renderOrders();
        break;
      case "items":
        body = renderItems();
        break;
      case "categories":
        body = renderCategories();
        break;
      case "new-invoice":
        body = renderNewInvoice();
        break;
      case "invoices":
        body = renderInvoicesList();
        break;
      case "earnings":
        body = renderEarnings();
        break;
      case "clients":
        body = renderClients();
        break;
      case "item-orders":
        body = renderItemOrders();
        break;
      case "bulk-invoice":
        body = renderBulkInvoice();
        break;
      case "bulk-orders":
        body = renderBulkOrdersList();
        break;
      case "bulk-order-view":
        body = renderBulkOrderView();
        break;
      case "invoice-view":
        body = renderInvoiceView();
        break;
      default:
        body = renderDashboard();
    }
    var html =
      renderSidebar() + '<div class="main">' + body + "</div>" + renderModal();
    document.getElementById("app").innerHTML = html;
    bindEvents();
  }

  /* ================= events ================= */
  /* binds the events for invoice line rows (qty, remove, and the item
     combobox). Called both on the whole page (inside bindEvents) and on a
     single freshly-swapped-in row (from updateLineRow), so typing in the
     item search box no longer has to re-render/re-bind the entire page. */
  function bindLineRowEvents(scope) {
    scope.querySelectorAll("[data-remove-line]").forEach(function (el) {
      el.addEventListener("click", function () {
        removeDraftLine(el.getAttribute("data-remove-line"));
      });
    });
    scope.querySelectorAll("[data-line]").forEach(function (el) {
      el.addEventListener("change", function () {
        updateDraftLine(
          el.getAttribute("data-line"),
          el.getAttribute("data-field"),
          el.value,
        );
      });
    });

    // item combobox (searchable item picker on invoice lines)
    scope.querySelectorAll("[data-combo-input]").forEach(function (el) {
      el.addEventListener("focus", function () {
        var lineId = el.getAttribute("data-combo-input");
        if (state.activeComboLine !== lineId) {
          var prevLineId = state.activeComboLine;
          state.activeComboLine = lineId;
          if (prevLineId) updateLineRow(prevLineId);
          updateLineRow(lineId);
        }
      });
      el.addEventListener("input", function () {
        var lineId = el.getAttribute("data-combo-input");
        var line = state.draft.lines.find(function (l) {
          return l.id === lineId;
        });
        if (line) {
          line.query = el.value;
          var currentItem = state.items.find(function (i) {
            return i.id === line.itemId;
          });
          if (currentItem && currentItem.name !== el.value) {
            line.itemId = "";
          }
        }
        state.activeComboLine = lineId;
        updateLineRow(lineId);
      });
      el.addEventListener("keydown", function (e) {
        if (e.key !== "Enter") return;
        e.preventDefault();
        var lineId = el.getAttribute("data-combo-input");
        var q = el.value.trim();
        if (!q) return;
        var exact = state.items.find(function (i) {
          return i.name.trim().toLowerCase() === q.toLowerCase();
        });
        if (exact) {
          selectComboItem(lineId, exact.id);
          return;
        }
        var matches = comboFilter(state.items, q);
        if (matches.length === 1) {
          selectComboItem(lineId, matches[0].id);
        } else if (matches.length === 0) {
          triggerQuickAddItem(lineId, q);
        }
      });
      el.addEventListener("blur", function () {
        var lineId = el.getAttribute("data-combo-input");
        setTimeout(function () {
          var stillFocused =
            document.activeElement &&
            document.activeElement.getAttribute &&
            document.activeElement.getAttribute("data-combo-input") === lineId;
          if (!stillFocused && state.activeComboLine === lineId) {
            state.activeComboLine = null;
            updateLineRow(lineId);
          }
        }, 150);
      });
    });
    scope.querySelectorAll("[data-combo-pick]").forEach(function (el) {
      el.addEventListener("mousedown", function (e) {
        e.preventDefault();
        selectComboItem(
          el.getAttribute("data-combo-pick"),
          el.getAttribute("data-combo-item-id"),
        );
      });
    });
    scope.querySelectorAll("[data-combo-quickadd]").forEach(function (el) {
      el.addEventListener("mousedown", function (e) {
        e.preventDefault();
        triggerQuickAddItem(
          el.getAttribute("data-combo-quickadd"),
          el.getAttribute("data-combo-quickadd-name"),
        );
      });
    });
  }

  function bindEvents() {
    var root = document.getElementById("app");

    root.querySelectorAll("[data-nav]").forEach(function (el) {
      el.addEventListener("click", function () {
        goTo(el.getAttribute("data-nav"));
      });
    });
    root.querySelectorAll("[data-view-invoice]").forEach(function (el) {
      el.addEventListener("click", function () {
        viewInvoice(el.getAttribute("data-view-invoice"));
      });
    });
    root.querySelectorAll("[data-view-client]").forEach(function (el) {
      el.addEventListener("click", function () {
        viewClientInvoices(el.getAttribute("data-view-client"));
      });
    });
    root.querySelectorAll("[data-view-month]").forEach(function (el) {
      el.addEventListener("click", function () {
        viewMonthInvoices(el.getAttribute("data-view-month"));
      });
    });
    root.querySelectorAll("[data-view-month-btn]").forEach(function (el) {
      el.addEventListener("click", function (e) {
        e.stopPropagation();
        viewMonthInvoices(el.getAttribute("data-view-month-btn"));
      });
    });
    root.querySelectorAll("[data-earnings-range]").forEach(function (el) {
      el.addEventListener("change", function () {
        var which = el.getAttribute("data-earnings-range");
        if (which === "from") state.earningsRangeFrom = el.value;
        else state.earningsRangeTo = el.value;
        render();
      });
    });
    var viewRangeBtn = root.querySelector("[data-view-range]");
    if (viewRangeBtn) {
      viewRangeBtn.addEventListener("click", function () {
        viewRangeInvoices(state.earningsRangeFrom, state.earningsRangeTo);
      });
    }
    root.querySelectorAll("[data-view-orders]").forEach(function (el) {
      el.addEventListener("click", function () {
        viewItemOrders(el.getAttribute("data-view-orders"));
      });
    });
    root.querySelectorAll("[data-new-order-item]").forEach(function (el) {
      el.addEventListener("click", function () {
        startDraftForItem(el.getAttribute("data-new-order-item"));
      });
    });
    root.querySelectorAll("[data-bill-order]").forEach(function (el) {
      el.addEventListener("click", function () {
        billOrder(el.getAttribute("data-bill-order"));
      });
    });
    root.querySelectorAll("[data-dismiss-order]").forEach(function (el) {
      el.addEventListener("click", function () {
        dismissOrder(el.getAttribute("data-dismiss-order"));
      });
    });
    root.querySelectorAll("[data-edit-invoice]").forEach(function (el) {
      el.addEventListener("click", function () {
        editInvoice(el.getAttribute("data-edit-invoice"));
      });
    });
    var clearFilter = root.querySelector("[data-clear-filter]");
    if (clearFilter)
      clearFilter.addEventListener("click", function () {
        state.clientFilter = null;
        state.monthFilter = null;
        state.rangeFilter = null;
        render();
      });

    var addItemBtn = root.querySelector("[data-add-item]");
    if (addItemBtn)
      addItemBtn.addEventListener("click", function () {
        openItemModal(null);
      });
    var newBulkBtn = root.querySelector("[data-new-bulk-invoice]");
    if (newBulkBtn)
      newBulkBtn.addEventListener("click", function () {
        startBulkInvoice();
      });
    root.querySelectorAll("[data-edit-item]").forEach(function (el) {
      el.addEventListener("click", function () {
        var item = state.items.find(function (i) {
          return i.id === el.getAttribute("data-edit-item");
        });
        openItemModal(item);
      });
    });
    root.querySelectorAll("[data-del-item]").forEach(function (el) {
      el.addEventListener("click", function () {
        confirmDeleteItem(el.getAttribute("data-del-item"));
      });
    });
    var addCategoryBtn = root.querySelector("[data-add-category]");
    if (addCategoryBtn)
      addCategoryBtn.addEventListener("click", function () {
        openCategoryModal(null);
      });
    root.querySelectorAll("[data-add-subcategory]").forEach(function (el) {
      el.addEventListener("click", function () {
        openCategoryModal(null, el.getAttribute("data-add-subcategory"));
      });
    });
    root.querySelectorAll("[data-edit-category]").forEach(function (el) {
      el.addEventListener("click", function () {
        var cat = state.categories.find(function (c) {
          return c.id === el.getAttribute("data-edit-category");
        });
        openCategoryModal(cat);
      });
    });
    root.querySelectorAll("[data-del-category]").forEach(function (el) {
      el.addEventListener("click", function () {
        confirmDeleteCategory(el.getAttribute("data-del-category"));
      });
    });
    var categoryForm = document.getElementById("category-form");
    if (categoryForm) {
      categoryForm.addEventListener("submit", function (e) {
        e.preventDefault();
        submitCategoryModal(categoryForm);
      });
    }
    var confirmDelCategory = root.querySelector(
      "[data-confirm-del-category]",
    );
    if (confirmDelCategory)
      confirmDelCategory.addEventListener("click", function () {
        var reassignSel = document.getElementById("catReassignSelect");
        deleteCategory(
          confirmDelCategory.getAttribute("data-confirm-del-category"),
          reassignSel ? reassignSel.value : null,
        );
      });
    root.querySelectorAll("[data-del-invoice]").forEach(function (el) {
      el.addEventListener("click", function () {
        confirmDeleteInvoice(el.getAttribute("data-del-invoice"));
      });
    });
    var printBtn = root.querySelector("[data-print]");
    if (printBtn)
      printBtn.addEventListener("click", function () {
        window.print();
      });

    root.querySelectorAll("[data-close-modal]").forEach(function (el) {
      el.addEventListener("click", function () {
        state.modal = null;
        render();
      });
    });
    var logoutBtn = root.querySelector("[data-logout]");
    if (logoutBtn) {
      logoutBtn.addEventListener("click", function () {
        logout();
      });
    }
    var changePassBtn = root.querySelector("[data-change-password]");
    if (changePassBtn) {
      changePassBtn.addEventListener("click", function () {
        state.modal = { type: "changePassword", payload: {} };
        render();
      });
    }
    var cpForm = document.getElementById("change-password-form");
    if (cpForm) {
      cpForm.addEventListener("submit", function (e) {
        e.preventDefault();
        submitChangePassword();
      });
    }
    var itemForm = document.getElementById("item-form");
    if (itemForm) {
      itemForm.addEventListener("submit", function (e) {
        e.preventDefault();
        submitItemModal(itemForm);
      });
      itemForm.addEventListener("click", function (e) {
        var addBtn = e.target.closest("[data-add-opt-row]");
        if (addBtn) {
          var kind = addBtn.getAttribute("data-add-opt-row");
          var container = document.getElementById(kind + "OptRows");
          if (container) {
            var wrap = document.createElement("div");
            wrap.innerHTML =
              kind === "color"
                ? colorRowsHtml([{ name: "", hex: "#B8842E" }])
                : optionRowsHtml(
                    [{ label: "", price: "" }],
                    kind,
                    kind === "size" ? "e.g. 6mm" : "e.g. 3 Pc",
                  );
            container.appendChild(wrap.firstChild);
          }
          return;
        }
        var removeBtn = e.target.closest("[data-remove-opt-row]");
        if (removeBtn) {
          var row = removeBtn.closest(".opt-row");
          if (row) row.remove();
        }
      });
      var imgHint = document.getElementById("imgUploadHint");
      var itemSubmit = document.getElementById("itemFormSubmit");
      var defaultHint =
        'Choose up to 4 photos from your phone or computer (JPG, PNG, WebP). The first photo is the main one shown on the catalog card; all 4 appear in the website\'s product gallery. Leave empty to use an automatic monogram badge. Quantity 0 just shows "Out of Stock" on the catalog card — use the Listing option above to move it into Pre-Booking.';
      [1, 2, 3, 4].forEach(function (n) {
        var imgFileInput = document.getElementById("imgFileInput" + n);
        var imgClearBtn = document.getElementById("imgClearBtn" + n);
        if (imgFileInput) {
          imgFileInput.addEventListener("change", function () {
            var file = imgFileInput.files && imgFileInput.files[0];
            if (!file) return;
            if (imgHint) imgHint.textContent = "Processing image…";
            if (itemSubmit) itemSubmit.disabled = true;
            compressImageFile(file)
              .then(function (dataUrl) {
                setImgPreview(n, dataUrl);
                if (imgHint) imgHint.textContent = defaultHint;
              })
              .catch(function (err) {
                if (imgHint)
                  imgHint.textContent =
                    (err && err.message) || "Could not use that image.";
              })
              .then(function () {
                if (itemSubmit) itemSubmit.disabled = false;
                imgFileInput.value = "";
              });
          });
        }
        if (imgClearBtn) {
          imgClearBtn.addEventListener("click", function () {
            setImgPreview(n, "");
          });
        }
      });
    }
    var confirmDelItem = root.querySelector("[data-confirm-del-item]");
    if (confirmDelItem)
      confirmDelItem.addEventListener("click", function () {
        deleteItem(confirmDelItem.getAttribute("data-confirm-del-item"));
      });
    var confirmDelInvoice = root.querySelector("[data-confirm-del-invoice]");
    if (confirmDelInvoice)
      confirmDelInvoice.addEventListener("click", function () {
        deleteInvoice(
          confirmDelInvoice.getAttribute("data-confirm-del-invoice"),
        );
      });
    root.querySelectorAll("[data-view-bulk-batch]").forEach(function (el) {
      el.addEventListener("click", function () {
        viewBulkBatch(el.getAttribute("data-view-bulk-batch"));
      });
    });
    root.querySelectorAll("[data-edit-bulk-batch]").forEach(function (el) {
      el.addEventListener("click", function () {
        editBulkBatch(el.getAttribute("data-edit-bulk-batch"));
      });
    });
    root.querySelectorAll("[data-del-bulk-batch]").forEach(function (el) {
      el.addEventListener("click", function () {
        confirmDeleteBulkBatch(el.getAttribute("data-del-bulk-batch"));
      });
    });
    var confirmDelBulkBatch = root.querySelector(
      "[data-confirm-del-bulk-batch]",
    );
    if (confirmDelBulkBatch)
      confirmDelBulkBatch.addEventListener("click", function () {
        deleteBulkBatch(
          confirmDelBulkBatch.getAttribute("data-confirm-del-bulk-batch"),
        );
      });

    var cancelBtn = root.querySelector("[data-cancel-draft]");
    if (cancelBtn) cancelBtn.addEventListener("click", cancelDraft);
    var saveBtn = root.querySelector("[data-save-draft]");
    if (saveBtn) saveBtn.addEventListener("click", saveDraftInvoice);

    var cancelBulkBtn = root.querySelector("[data-cancel-bulk]");
    if (cancelBulkBtn) cancelBulkBtn.addEventListener("click", cancelBulkInvoice);
    var saveBulkBtn = root.querySelector("[data-save-bulk]");
    if (saveBulkBtn) saveBulkBtn.addEventListener("click", saveBulkInvoice);
    var addBulkRowBtn = root.querySelector("[data-add-bulk-row]");
    if (addBulkRowBtn) addBulkRowBtn.addEventListener("click", addBulkRow);
    root.querySelectorAll("[data-remove-bulk-row]").forEach(function (el) {
      el.addEventListener("click", function () {
        removeBulkRow(el.getAttribute("data-remove-bulk-row"));
      });
    });
    var bulkItemSelect = root.querySelector("[data-bulk-item]");
    if (bulkItemSelect)
      bulkItemSelect.addEventListener("change", function () {
        updateBulkItem(bulkItemSelect.value);
      });
    root.querySelectorAll("[data-bulk-row]").forEach(function (el) {
      var field = el.getAttribute("data-bulk-field");
      if (field === "qty") {
        el.addEventListener("change", function () {
          updateBulkRow(el.getAttribute("data-bulk-row"), "qty", el.value);
          render();
        });
      } else {
        el.addEventListener("input", function () {
          updateBulkRow(el.getAttribute("data-bulk-row"), "name", el.value);
        });
      }
    });
    var addLineBtn = root.querySelector("[data-add-line]");
    if (addLineBtn) addLineBtn.addEventListener("click", addDraftLine);
    bindLineRowEvents(root);
    root.querySelectorAll("[data-draft-field]").forEach(function (el) {
      el.addEventListener("input", function () {
        updateDraftField(el.getAttribute("data-draft-field"), el.value);
        if (el.getAttribute("data-draft-field") === "deliveryCharges") {
          refreshDraftTotals();
        }
      });
      el.addEventListener("change", function () {
        updateDraftField(el.getAttribute("data-draft-field"), el.value);
        if (el.getAttribute("data-draft-field") === "deliveryCharges") {
          refreshDraftTotals();
        }
      });
    });

    // inventory search box
    var itemSearchEl = root.querySelector("[data-item-search]");
    if (itemSearchEl) {
      itemSearchEl.addEventListener("input", function () {
        state.itemSearchQuery = itemSearchEl.value;
        withPreservedFocus(render);
      });
    }

    // clients search box
    var clientSearchEl = root.querySelector("[data-client-search]");
    if (clientSearchEl) {
      clientSearchEl.addEventListener("input", function () {
        state.clientSearchQuery = clientSearchEl.value;
        withPreservedFocus(render);
      });
    }
  }

  boot();
})();