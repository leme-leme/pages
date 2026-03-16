"use client";

import { forwardRef, useMemo, useState, useCallback, useEffect, useRef } from "react";
import "./edit-component.css";
import Select, { components } from "react-select";
import CreatableSelect from "react-select/creatable";
import { ChevronDown, X } from "lucide-react";
import { safeAccess, interpolate } from "@/lib/schema";

const Option = ({ children, ...props }: any) => {
  const { data } = props;
  return (
    <components.Option {...props}>
      <div className="flex items-center gap-2">
        {data.image && <img src={data.image} alt="" className="w-6 h-6 rounded-full" />}
        {children}
      </div>
    </components.Option>
  );
};

const SingleValue = ({ children, ...props }: any) => {
  const { data } = props;
  return (
    <components.SingleValue {...props}>
      <div className="flex items-center gap-2">
        {data.image && <img src={data.image} alt="" className="w-6 h-6 rounded-full" />}
        {children}
      </div>
    </components.SingleValue>
  );
};

const DropdownIndicator = (props: any) => (
  <components.DropdownIndicator {...props}>
    <ChevronDown className="w-4 h-4" />
  </components.DropdownIndicator>
);

const ClearIndicator = (props: any) => (
  <components.ClearIndicator {...props}>
    <X className="w-4 h-4" />
  </components.ClearIndicator>
);

const MultiValueRemove = (props: any) => (
  <components.MultiValueRemove {...props}>
    <X className="w-3 h-3 stroke-[2.5]" />
  </components.MultiValueRemove>
);

type FetchConfig = {
  url: string;
  method?: string;
  params?: Record<string, string>;
  headers?: Record<string, string>;
  results?: string;
  value?: string;
  label?: string;
  minlength?: number;
  image?: string;
};

const PAGE_SIZE = 50;

const EditComponent = forwardRef((props: any, ref: any) => {
  const { value, field, onChange } = props;
  const isMultiple: boolean = !!field.options?.multiple;
  const fetchConfig = field.options?.fetch as FetchConfig | undefined;

  const [isMounted, setIsMounted] = useState(false);
  useEffect(() => setIsMounted(true), []);

  // Static options (non-fetch selects)
  const staticOptions = useMemo(
    () =>
      !fetchConfig && field.options?.values
        ? field.options.values.map((opt: any) =>
            typeof opt === "object"
              ? { value: opt.value, label: opt.label }
              : { value: opt, label: opt }
          )
        : [],
    [field.options?.values, fetchConfig]
  );

  // ── Fetch-based state ──────────────────────────────────────────────────────

  const [fetchedOptions, setFetchedOptions] = useState<any[]>([]);
  const [isFetchLoading, setIsFetchLoading] = useState(false);
  const [hasMore, setHasMore] = useState(false);
  const [fetchInputValue, setFetchInputValue] = useState("");

  const isFetchingRef = useRef(false);
  const offsetRef = useRef(0);
  const searchInputRef = useRef("");
  const requestIdRef = useRef(0);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>();
  const initialLoadDoneRef = useRef(false);
  const resolutionAttemptedRef = useRef<Set<string>>(new Set());

  const doFetch = useCallback(
    async (input: string, offset: number, append: boolean) => {
      if (!fetchConfig?.url) return;
      if (isFetchingRef.current) return;

      const minLen = fetchConfig.minlength ?? 0;
      if (input.length < minLen) {
        if (!append) setFetchedOptions([]);
        return;
      }

      const requestId = ++requestIdRef.current;
      isFetchingRef.current = true;
      setIsFetchLoading(true);

      try {
        const sp = new URLSearchParams();
        if (fetchConfig.params) {
          for (const [k, v] of Object.entries(fetchConfig.params)) {
            if (k === "limit") continue; // controlled below
            sp.set(k, interpolate(v, { input }, "fields"));
          }
        }
        sp.set("limit", String(PAGE_SIZE));
        sp.set("offset", String(offset));

        const response = await fetch(`${fetchConfig.url}?${sp}`, {
          method: fetchConfig.method || "GET",
          headers: fetchConfig.headers || {},
        });
        if (!response.ok) throw new Error("Fetch failed");

        // Stale response — a newer request was started
        if (requestId !== requestIdRef.current) return;

        const data = await response.json();
        const results = fetchConfig.results ? safeAccess(data, fetchConfig.results) : data;
        if (!Array.isArray(results)) return;

        const newOpts = results.map((item: any) => ({
          value: fetchConfig.value ? interpolate(fetchConfig.value, item, "fields") : item.id,
          label: fetchConfig.label ? interpolate(fetchConfig.label, item, "fields") : item.name,
          image: fetchConfig.image ? interpolate(fetchConfig.image, item, "fields") : undefined,
        }));

        offsetRef.current = offset + results.length;
        setHasMore(results.length === PAGE_SIZE);
        setFetchedOptions((prev) => (append ? [...prev, ...newOpts] : newOpts));
      } catch (e) {
        console.error("Error fetching options:", e);
      } finally {
        isFetchingRef.current = false;
        setIsFetchLoading(false);
      }
    },
    [fetchConfig]
  );

  // Initial load when minlength === 0
  useEffect(() => {
    if (!isMounted || !fetchConfig || initialLoadDoneRef.current) return;
    const minLen = fetchConfig.minlength ?? 0;
    if (minLen === 0) {
      initialLoadDoneRef.current = true;
      offsetRef.current = 0;
      doFetch("", 0, false);
    }
  }, [isMounted, fetchConfig, doFetch]);

  // Cleanup debounce on unmount
  useEffect(() => () => { clearTimeout(debounceRef.current); }, []);

  // Controlled search input — debounced fetch
  const handleInputChange = useCallback(
    (val: string) => {
      setFetchInputValue(val);
      searchInputRef.current = val;
      clearTimeout(debounceRef.current);
      debounceRef.current = setTimeout(() => {
        isFetchingRef.current = false; // cancel in-flight
        offsetRef.current = 0;
        doFetch(val, 0, false);
      }, 300);
    },
    [doFetch]
  );

  // Infinite scroll — triggered by react-select's onMenuScrollToBottom
  const handleScrollToBottom = useCallback(() => {
    if (!hasMore || isFetchingRef.current) return;
    doFetch(searchInputRef.current, offsetRef.current, true);
  }, [hasMore, doFetch]);

  // ── Selected options state ─────────────────────────────────────────────────

  const [selectedOptions, setSelectedOptions] = useState(() => {
    if (isMultiple) {
      const values = Array.isArray(value)
        ? value
        : typeof value === "string" && value
          ? value.split(",").map((s: string) => s.trim()).filter(Boolean)
          : [];
      return values.map((val: any) => ({ value: val, label: val }));
    }
    if (!value) return null;
    return { value, label: value };
  });

  // Once options load, update labels of pre-selected items (slug → title)
  useEffect(() => {
    if (!fetchedOptions.length || !fetchConfig) return;
    setSelectedOptions((prev: any) => {
      if (!prev) return prev;
      const update = (sel: any) => {
        const match = fetchedOptions.find((o) => o.value === sel.value);
        return match && match.label !== sel.label ? { ...sel, label: match.label } : sel;
      };
      if (Array.isArray(prev)) {
        const next = prev.map(update);
        return next.some((o: any, i: number) => o !== prev[i]) ? next : prev;
      }
      const next = update(prev);
      return next !== prev ? next : prev;
    });
  }, [fetchedOptions, fetchConfig]);

  // Resolve labels for pre-selected items not covered by initial page load
  // (e.g. items from letter B-Z when first page only has A's)
  useEffect(() => {
    if (!isMounted || !fetchConfig?.url) return;
    const current = Array.isArray(selectedOptions) ? selectedOptions : selectedOptions ? [selectedOptions] : [];
    const unresolved = current.filter(
      (o: any) => o.label === o.value && !resolutionAttemptedRef.current.has(o.value)
    );
    if (unresolved.length === 0) return;

    unresolved.forEach((sel: any) => {
      resolutionAttemptedRef.current.add(sel.value);

      // Extract filename stem from path for search (e.g. "content/woorden/b/bakra.md" → "bakra")
      const pathParts = sel.value.split("/");
      const filename = pathParts[pathParts.length - 1];
      const searchQuery = filename.includes(".") ? filename.split(".").slice(0, -1).join(".") : filename;

      const sp = new URLSearchParams();
      if (fetchConfig.params) {
        for (const [k, v] of Object.entries(fetchConfig.params)) {
          if (k === "limit" || k === "offset" || k === "query") continue;
          sp.set(k, interpolate(v as string, { input: searchQuery }, "fields"));
        }
      }
      sp.set("query", searchQuery);
      sp.set("limit", "10");
      sp.set("offset", "0");

      fetch(`${fetchConfig.url}?${sp}`, {
        method: fetchConfig.method || "GET",
        headers: fetchConfig.headers || {},
      })
        .then((r) => (r.ok ? r.json() : null))
        .then((data) => {
          if (!data) return;
          const results = fetchConfig.results ? safeAccess(data, fetchConfig.results) : data;
          if (!Array.isArray(results)) return;

          const match = results.find((item: any) => {
            const val = fetchConfig.value ? interpolate(fetchConfig.value, item, "fields") : item.id;
            return val === sel.value;
          });
          if (!match) return;

          const resolvedLabel = fetchConfig.label
            ? interpolate(fetchConfig.label, match, "fields")
            : match.name || sel.value;
          if (resolvedLabel === sel.value) return;

          setSelectedOptions((prev: any) => {
            if (!prev) return prev;
            const update = (o: any) =>
              o.value === sel.value ? { ...o, label: resolvedLabel } : o;
            if (Array.isArray(prev)) {
              const next = prev.map(update);
              return next.some((o: any, i: number) => o !== prev[i]) ? next : prev;
            }
            return update(prev);
          });
        })
        .catch((e) => console.error("Label resolution failed for", sel.value, e));
    });
  }, [isMounted, selectedOptions, fetchConfig]);

  const handleChange = useCallback(
    (newValue: any) => {
      setSelectedOptions(newValue ?? (isMultiple ? [] : null));
      const output = isMultiple
        ? newValue ? newValue.map((item: any) => item.value) : []
        : newValue ? newValue.value : null;
      onChange(output);
    },
    [onChange, isMultiple]
  );

  if (!isMounted) return null;

  const sharedComponents = {
    DropdownIndicator,
    ClearIndicator,
    MultiValueRemove,
    Option,
    SingleValue,
  };

  // ── Fetch-based select ─────────────────────────────────────────────────────
  if (fetchConfig) {
    const SelectComp = field.options?.creatable ? CreatableSelect : Select;
    return (
      <SelectComp
        ref={ref}
        isMulti={isMultiple}
        isClearable={true}
        hideSelectedOptions={false}
        closeMenuOnSelect={!isMultiple}
        classNamePrefix="react-select"
        placeholder={field.options?.placeholder || "Select..."}
        noOptionsMessage={({ inputValue }: { inputValue: string }) =>
          isFetchLoading ? null : inputValue ? "No results" : "Type to search"
        }
        loadingMessage={() => "Loading..."}
        isLoading={isFetchLoading}
        options={fetchedOptions}
        value={selectedOptions}
        onChange={handleChange}
        inputValue={fetchInputValue}
        onInputChange={handleInputChange}
        filterOption={() => true}
        onMenuScrollToBottom={handleScrollToBottom}
        components={sharedComponents}
      />
    );
  }

  // ── Static select ──────────────────────────────────────────────────────────
  const StaticComp = field.options?.creatable ? CreatableSelect : Select;
  return (
    <StaticComp
      ref={ref}
      isMulti={isMultiple}
      isClearable={true}
      hideSelectedOptions={false}
      closeMenuOnSelect={!isMultiple}
      classNamePrefix="react-select"
      placeholder={field.options?.placeholder || "Select..."}
      noOptionsMessage={() => "No options"}
      options={staticOptions}
      value={selectedOptions}
      onChange={handleChange}
      components={sharedComponents}
    />
  );
});

export { EditComponent };
