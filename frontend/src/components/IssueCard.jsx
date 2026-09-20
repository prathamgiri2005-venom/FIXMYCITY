import { motion } from "framer-motion";
import { ArrowBigUp, MapPin, Clock, Wrench } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import StatusBadge from "./StatusBadge";
import CategoryTag from "./CategoryTag";
import { imgUrl } from "../api";

export default function IssueCard({ issue, index = 0, onUpvote }) {
  return (
    <motion.article
      data-testid={`issue-card-${issue.id}`}
      initial={{ opacity: 0, y: 24 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(index * 0.06, 0.6), duration: 0.45, ease: "easeOut" }}
      className="glass overflow-hidden hover:border-white/20 transition-colors duration-300"
    >
      {issue.image_url && (
        <div className="relative h-44 overflow-hidden">
          <img
            src={imgUrl(issue.image_url)}
            alt={issue.category}
            className="h-full w-full object-cover transition-transform duration-500 hover:scale-105"
            loading="lazy"
          />
          <div className="absolute inset-x-0 top-0 flex items-start justify-between p-3 bg-gradient-to-b from-black/60 to-transparent">
            <CategoryTag category={issue.category} />
            <StatusBadge status={issue.status} />
          </div>
        </div>
      )}
      <div className="p-4 space-y-3">
        {!issue.image_url && (
          <div className="flex items-center gap-2">
            <CategoryTag category={issue.category} />
            <StatusBadge status={issue.status} />
          </div>
        )}
        <p className="text-sm text-slate-200 leading-relaxed line-clamp-3">{issue.description}</p>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400">
          <span className="inline-flex items-center gap-1">
            <MapPin className="h-3.5 w-3.5 text-cyan-400" />
            {issue.area}
            {issue.distance_km != null && <span className="text-cyan-300">· {issue.distance_km} km</span>}
          </span>
          <span className="inline-flex items-center gap-1">
            <Clock className="h-3.5 w-3.5" />
            {issue.created_at ? formatDistanceToNow(new Date(issue.created_at), { addSuffix: true }) : ""}
          </span>
        </div>
        {issue.assigned_to && (
          <div className="inline-flex items-center gap-1.5 text-xs text-violet-300">
            <Wrench className="h-3.5 w-3.5" />
            {issue.assigned_to.name} · {issue.assigned_to.dept}
          </div>
        )}
        <div className="flex items-center justify-between pt-1 border-t border-white/5">
          <div className="flex items-center gap-2 pt-2">
            <span className="grid h-7 w-7 place-items-center rounded-full bg-gradient-to-br from-cyan-500/30 to-violet-500/30 text-[11px] font-bold text-cyan-200 border border-white/10">
              {(issue.author?.name || "C").slice(0, 1)}
            </span>
            <span className="text-xs text-slate-400">{issue.author?.name}</span>
          </div>
          <button
            data-testid={`upvote-btn-${issue.id}`}
            onClick={() => onUpvote && onUpvote(issue)}
            className={`mt-2 inline-flex items-center gap-1.5 rounded-full border px-3.5 py-1.5 text-xs font-semibold transition-all duration-200 active:scale-90 ${
              issue.upvoted
                ? "border-cyan-400/60 bg-cyan-400/15 text-cyan-300 shadow-[0_0_14px_rgba(0,240,255,0.25)]"
                : "border-white/10 bg-white/5 text-slate-300 hover:border-cyan-400/40 hover:text-cyan-300"
            }`}
          >
            <ArrowBigUp className={`h-4 w-4 ${issue.upvoted ? "fill-cyan-400/40" : ""}`} />
            {issue.upvotes}
          </button>
        </div>
      </div>
    </motion.article>
  );
}
