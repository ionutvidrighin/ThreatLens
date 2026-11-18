import { NavLink } from "react-router"
import { cn } from "@/lib/cn"
import { sidemenuSections } from "@/routes"

const linkBase =
	"mb-1.5 flex min-h-11 items-center gap-3.5 rounded-[9px] px-3.5 py-3 text-[13px] font-medium text-muted no-underline max-[760px]:m-0 max-[760px]:py-2.5"

const sectionLabel =
	"mx-3.5 mb-3 text-[10px] font-semibold tracking-[0.8px] text-faint max-[760px]:hidden"

export const Sidebar = () => {
	return (
		<aside className="flex flex-col overflow-y-auto border-r border-line bg-sidebar px-4.5 py-8 max-[760px]:border-r-0 max-[760px]:border-b max-[760px]:px-5 max-[760px]:py-4">
			<nav
				aria-label="Main navigation"
				className="max-[760px]:flex max-[760px]:flex-wrap max-[760px]:gap-1.5"
			>
				{sidemenuSections.map((section) => (
					// `contents` on small screens: the section wrappers disappear so all
					// links flow in one wrapping row.
					<div key={section.label} className="mb-5 max-[760px]:contents">
						<p className={`${sectionLabel} -ml-1`}>{section.label}</p>
						{section.items.map((item) => (
							<NavLink
								key={item.to}
								to={item.to}
								className={({ isActive }) =>
									cn(
										linkBase,
										isActive
											? "bg-surface font-bold text-heading"
											: "hover:bg-hover hover:text-heading",
									)
								}
							>
								<item.icon size={18} strokeWidth={1.6} aria-hidden="true" />
								{item.label}
							</NavLink>
						))}
					</div>
				))}
			</nav>
		</aside>
	)
}
