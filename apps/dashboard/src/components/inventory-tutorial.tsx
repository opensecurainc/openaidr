"use client";

import { useEffect, useRef, useState } from "react";
import { CirclePlay } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

const videoUrl = "/tutorials/ai-apps.mp4";

export function InventoryTutorial() {
  const [open, setOpen] = useState(false);
  const videoRef = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    const video = videoRef.current;
    return () => video?.pause();
  }, [open]);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="link" size="heading">
          <CirclePlay aria-hidden="true" />
          Watch tutorial
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-5xl">
        <DialogHeader className="pr-6">
          <DialogTitle>AI Apps tutorial</DialogTitle>
          <DialogDescription>
            Review apps, inspect risks, and record approval decisions.
            {" "}2 min 39 sec, with narration and captions. Uses sample data.
          </DialogDescription>
        </DialogHeader>
        <video
          ref={videoRef}
          aria-label="AI Apps tutorial video"
          className="aspect-video w-full rounded-md bg-muted"
          controls
          playsInline
          preload="none"
          poster="/tutorials/ai-apps.jpg"
          src={videoUrl}
        />
        <a
          href={videoUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="w-fit rounded-sm text-sm text-primary underline underline-offset-4 focus-visible:outline-2 focus-visible:outline-ring"
        >
          Open video in a new tab
        </a>
      </DialogContent>
    </Dialog>
  );
}
