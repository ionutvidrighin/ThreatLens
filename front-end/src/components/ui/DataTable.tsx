import {
	type ColumnDef,
	createColumnHelper,
	type RowData,
	tableFeatures,
	useTable,
} from "@tanstack/react-table"
import { Table, Td, Th } from "./Table"

// Core table only (no sorting/filtering/pagination): all of that happens on the
// server. Register more features here when a table needs them.
const features = tableFeatures({})

/**
 * Typed column helper for DataTable.
 *
 * @example
 * const column = createColumn<SecurityAlert>()
 * const columns = column.columns([
 *   column.accessor("ruleName", { header: "Rule" }),
 *   column.accessor("severity", {
 *     header: "Severity",
 *     cell: (info) => <SeverityBadge severity={info.getValue()} />,
 *   }),
 * ])
 *
 * Define `columns` OUTSIDE the component (module scope) so the table gets the
 * same array on every render.
 */
export const createColumn = <TData extends RowData>() =>
	createColumnHelper<typeof features, TData>()

export type DataTableColumns<TData extends RowData> = ColumnDef<
	typeof features,
	TData
>[]

type DataTableProps<TData extends RowData> = {
	/** Screen-reader caption describing the table. */
	caption: string
	columns: DataTableColumns<TData>
	data: TData[]
	/** Stable unique id per row (e.g. alertId). Falls back to the row index. */
	getRowId?: (row: TData) => string
	/** Extra classes for a row's <tr> (e.g. to highlight specific rows). */
	getRowClassName?: (row: TData) => string | undefined
	emptyMessage?: string
	/**
	 * Classes for the scroll wrapper. Add a height limit such as `max-h-[65vh]`
	 * to make the rows scroll while the header row stays pinned.
	 */
	className?: string
}

export const DataTable = <TData extends RowData>({
	caption,
	columns,
	data,
	getRowId,
	getRowClassName,
	emptyMessage = "No results.",
	className,
}: DataTableProps<TData>) => {
	const table = useTable({
		features,
		columns,
		data,
		getRowId: getRowId ? (row) => getRowId(row) : undefined,
	})

	const rows = table.getRowModel().rows

	return (
		<Table caption={caption} className={className}>
			<thead>
				{table.getHeaderGroups().map((group) => (
					<tr key={group.id}>
						{group.headers.map((header) => (
							<Th key={header.id}>
								{header.isPlaceholder ? null : (
									<table.FlexRender header={header} />
								)}
							</Th>
						))}
					</tr>
				))}
			</thead>
			<tbody>
				{rows.length === 0 ? (
					<tr>
						<Td colSpan={columns.length} className="text-center">
							{emptyMessage}
						</Td>
					</tr>
				) : (
					rows.map((row) => (
						<tr key={row.id} className={getRowClassName?.(row.original)}>
							{row.getAllCells().map((cell) => (
								<Td key={cell.id}>
									<table.FlexRender cell={cell} />
								</Td>
							))}
						</tr>
					))
				)}
			</tbody>
		</Table>
	)
}
