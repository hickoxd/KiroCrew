import type { ReactNode } from 'react'
import { ContextMenu, ContextMenuTrigger, ContextMenuContent, ContextMenuItem } from './ui/context-menu'
import { i18nT } from '../i18n/t'

/**
 * Open a chip's close menu from a touch hold that lifted in place
 * (`useLongPressReorder`'s `onHoldRelease`). The Radix trigger opens on
 * `contextmenu` and positions at the event's point, so the release becomes the
 * event a right-click at that point would have produced. It is dispatched on
 * the tab inside the held item, so it bubbles through whichever element carries
 * the trigger: the item itself on the workspace strip, the chip on the terminal
 * strip (whose menu also holds Rename). A `disabled` trigger ignores it, exactly
 * as it ignores a right-click.
 */
export function openTabCloseMenu(e: PointerEvent, target: HTMLElement): void {
  const tab = target.matches('[role="tab"]') ? target : target.querySelector<HTMLElement>('[role="tab"]') ?? target
  tab.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: e.clientX, clientY: e.clientY }))
}

export interface TabCloseActions {
  closeOthersDisabled: boolean
  closeRightDisabled: boolean
  onClose: () => void
  onCloseOthers: () => void
  onCloseRight: () => void
  onCloseAll: () => void
}

/** Close, Close other tabs, Close tabs to the right, Close all tabs, for a
 *  chip whose context menu carries other items as well. */
export function TabCloseMenuItems({ closeOthersDisabled, closeRightDisabled, onClose, onCloseOthers, onCloseRight, onCloseAll }: TabCloseActions) {
  return (
    <>
      <ContextMenuItem className="[@media(pointer:coarse)]:min-h-11" onSelect={onClose}>
        {i18nT('components.bottomTerminalPanel.close_tab')}
      </ContextMenuItem>
      <ContextMenuItem className="[@media(pointer:coarse)]:min-h-11" disabled={closeOthersDisabled} onSelect={onCloseOthers}>
        {i18nT('components.bottomTerminalPanel.close_other_tabs')}
      </ContextMenuItem>
      <ContextMenuItem className="[@media(pointer:coarse)]:min-h-11" disabled={closeRightDisabled} onSelect={onCloseRight}>
        {i18nT('components.bottomTerminalPanel.close_tabs_to_right')}
      </ContextMenuItem>
      <ContextMenuItem className="[@media(pointer:coarse)]:min-h-11" onSelect={onCloseAll}>
        {i18nT('components.bottomTerminalPanel.close_all_tabs')}
      </ContextMenuItem>
    </>
  )
}

/** The close menu on right-click, or on touch by holding the chip and lifting
 *  without moving (see `openTabCloseMenu`). */
export default function TabCloseMenu({ children, disabled = false, ...actions }: TabCloseActions & {
  children: ReactNode
  disabled?: boolean
}) {
  return (
    <ContextMenu>
      <ContextMenuTrigger asChild disabled={disabled}>{children}</ContextMenuTrigger>
      <ContextMenuContent className="min-w-[190px]">
        <TabCloseMenuItems {...actions} />
      </ContextMenuContent>
    </ContextMenu>
  )
}
