
library(shiny)
library(mc2d)
library(ggplot2)
library(scales)
library(dplyr)
library(reshape2)
library(countrycode)

#1. Read the cleaned file


ps=read.csv("./Inputs/post2008sector.csv",stringsAsFactors=FALSE)

#read the country table
#countrytable=read.csv("~/Inputs/countrycodetable.csv",stringsAsFactors=FALSE)

#add the selection variables
#countries=sort(countrytable$fullname)
mysectors=unique(ps$sector)

ps=tbl_df(ps)

#convert all names to lower case
names(ps)=tolower(names(ps))

  #convert timeline incident year to factors
ps$timeline.incident.year=factor(ps$timeline.incident.year)

# find all incidents all kinds for sectors by years 


breachdetails=ps%>%
  select(Victim=victim.victim_id,Sector=sector,Pattern=pattern,Incident.Year=timeline.incident.year,Source.Reference=reference,Summary=summary)

ps.avail=ps%>%
  select(754:763,sector)%>%
  filter(sector=='Public Administration')%>%
  select(-sector)%>%
  mutate_each(funs(as.numeric))

# let's get the averages for compromise first by sector

  
ps.avail=melt(ps.avail,na.rm = T,value.name = "no.attacks",variable.name = "availability.duration")
ps.avail=ps.avail%>%
  group_by(availability.duration)%>%
  summarise(TotalCount=sum(no.attacks))

