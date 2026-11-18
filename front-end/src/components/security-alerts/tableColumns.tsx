import type { SecurityAlert } from "@/api/types"
import { Badge } from "../ui/Badge"
import { createColumn } from "../ui/DataTable"

const column = createColumn<SecurityAlert>()

export const tableColumns = column.columns([
	column.accessor("severity", {
		header: "Severity",
		cell: (info) => <Badge tone={info.getValue()}>{info.getValue()}</Badge>,
	}),
	column.accessor("ruleName", {
		header: "Detection Rule",
		cell: (info) => <div className="w-35 text-wrap">{info.getValue()}</div>,
	}),
	column.accessor("sourceIp", { header: "Source Ip" }),
	column.accessor("createdAt", {
		header: "Detected at",
		cell: (info) => new Date(info.getValue()).toLocaleString("ro-RO"),
	}),
	column.accessor("alertId", {
		header: "Alert ID",
		cell: (info) => (
			<div className="max-w-20 truncate" title={info.getValue()}>
				{info.getValue()}
			</div>
		),
	}),
	column.accessor("status", {
		header: "Status",
		cell: (info) => <div className="capitalize">{info.getValue()}</div>,
	}),
	column.accessor("failedAttempts", {
		header: "Failed Attempts",
		cell: (info) => (
			<div className="w-5">
				{info.getValue() ? (
					<span className="text-accent-red font-semibold">
						{info.getValue()}
					</span>
				) : (
					<span>-</span>
				)}
				<span></span>
			</div>
		),
	}),
	column.accessor("targetedAccounts", {
		header: "Targeted Accounts",
		cell: (info) => (
			<div className="w-5">
				{info.getValue() ? (
					<span className="text-accent-red font-semibold">
						{info.getValue()}
					</span>
				) : (
					<span>-</span>
				)}
				<span></span>
			</div>
		),
	}),
	column.accessor("usernames", {
		header: "Affected users",
		cell: (info) => (
			<div className="w-20 text-wrap">
				{info.getValue() ? (
					<>
						<span>[</span>
						<span className=" font-semibold text-accent-red">
							{" "}
							{info.getValue()?.join(", ")}{" "}
						</span>
						<span>]</span>
					</>
				) : (
					<span> - </span>
				)}
			</div>
		),
	}),
	column.accessor("description", {
		header: "Description",
		cell: (info) => <div className="w-45 text-wrap">{info.getValue()}</div>,
	}),
	column.accessor("entityType", { header: "Entity Type" }),
])
