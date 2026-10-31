export function SkeletonGrid({ count = 3 }: { count?: number }) { return <div className="stats-grid">{Array.from({ length: count }, (_, i) => <div key={i} className="skeleton-card" />)}</div>; }
