"use client";
import { useEffect, useRef, useState } from "react";
export function useRemote<T>(loader: () => Promise<T>) {
  const loaderRef = useRef(loader); loaderRef.current = loader;
  const [data, setData] = useState<T | null>(null); const [loading, setLoading] = useState(true); const [error, setError] = useState(false); const [reload, setReload] = useState(0);
  useEffect(() => { let live = true; setLoading(true); setError(false); void loaderRef.current().then((value) => { if (live) { setData(value); setLoading(false); } }).catch(() => { if (live) { setError(true); setLoading(false); } }); return () => { live = false; }; }, [reload]);
  return { data, loading, error, retry: () => setReload((n) => n + 1) };
}
