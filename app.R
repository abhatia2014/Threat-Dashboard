# load required libraries
library(shiny)
library(shinydashboard)
library(ggplot2)
library(dplyr)
library(scales)
library(reshape2)

#source("~/Datasets/Cyber_Risk_Evaluation/Cyber Risk Evaluation Tool/control.helper.R")
source("./threatanalysis.R")

# a dashboard has 3 parts- header, sidebar, body

#app.R

#the basic dashboard

ui=dashboardPage(skin = "red",
  dashboardHeader(title = "Threat Analysis (Courtesy VERIS Database)",titleWidth = 500),
  dashboardSidebar(
    # we will now add content to the sidebar
    #we add menu items that behave as shiny's tabpanels
    sidebarMenu(
      
      menuItem("Threat Assessment",tabName = "threatass",icon=icon("shield"),
               menuSubItem("Breach Trends",tabName = "histtrends",icon = icon("delicious"))
               
    ))),
  
  dashboardBody(
    #boxes need to be put in a row or column
    # in the body add tabItems with corresponding values for tabnames
    tabItems(
     
     #****Threat assessment UI
     # historical trends
     
     
     #breach analysis
     tabItem(
       tabName = 'histtrends',
       
       fluidRow(
         box(textOutput("breanaintro"),width = 10,solidHeader = TRUE,background = "black")
       ),
       fluidRow(
         box(textOutput("breanaheading2"),width = 6,solidHeader = TRUE,background = "blue")
       ),
       
       fluidRow(
         column(6, selectInput(inputId = "breanasec",label = "Please select sector for analysis",choices = 
                                 mysectors,selected = mysectors[1])),
         column(6, selectInput(inputId = "breanaact",label = "Please select actor type for analysis",choices = 
                                 c("All","External Actor Country","External Actor types","Internal Actor types","External Actor Motives","Internal Actor Motives","Partner Actor Motives"),selected = "All"))
       ),
       fluidRow(
         box(plotOutput("breanaplot1"),width = 10)
       ),
       fluidRow(
         box(textOutput("breanaheading3"),width = 6,solidHeader = TRUE,background = "blue")
       ),
       
       fluidRow(
         column(6, selectInput(inputId = "breanaattsec",label = "Please select sector for analysis",choices = 
                                 mysectors,selected = mysectors[1])),
         column(6, selectInput(inputId = "breanaattopt",label = "Please select attack type for analysis",choices = 
                                 c("All","Hacking","Malware","Social","Misuse","Error","Environmental"),selected = "All"))
       ),
       fluidRow(
         box(plotOutput("breanaplot2"),width = 10)
       ),
       fluidRow(
         box(textOutput("breanaheading4"),width = 6,solidHeader = TRUE,background = "blue")
       ),
       
       fluidRow(
         column(6, selectInput(inputId = "breanaastsec",label = "Please select sector for analysis",choices = 
                                 mysectors,selected = mysectors[1])),
         column(6, selectInput(inputId = "breanaastopt",label = "Please select attack type for analysis",choices = 
                                 c("All Assets","Asset Varieties","Attribute Availability Loss","Attribute Confidentiality Data Loss","Attribute Integrity Loss","Discovery Methods External","Discovery Methods Internal"),selected = "All"))
       ),
       fluidRow(
         box(plotOutput("breanaplot3"),width = 10)
       )
   
     ))))

 server=function(input,output){
  
  
   
 
 
  #**breach analytics
  datapull=reactive({
    
    selsector=input$selsec
    if (selsector=="All"){
     
       sectorsummary=breachdetails%>%
         select(Sector,Pattern,Incident.Year)%>%
        group_by(Sector,Incident.Year,Pattern)%>%
        summarize(count=n())
      
    }else {
      sectorsummary=breachdetails%>%
        filter(Sector==selsector)%>%
        select(Pattern,Incident.Year)%>%
        group_by(Incident.Year,Pattern)%>%
        summarize(count=n())
      
    }
 
  })
  
  output$threatintro=renderText({
    "This page provides a historical account of breaches by sectors that have hit the market since 2009. The data table at the bottom provides a brief summary of the breach."
  })
  
  output$sectorplot=renderPlot(height = 600,{
    plotdata=datapull()
    selsector=input$selsec
    if (selsector=="All"){
      ggplot(plotdata,aes(Incident.Year,count,fill=Incident.Year))+geom_bar(stat="identity")+theme_bw()+
        facet_wrap(~Sector,nrow = 7)+theme(legend.position="bottom")+
        xlab("Year 2009- 2014")+ylab("# Breaches")+ggtitle("# Breaches by Industry and Year")
      
    } else {
      
      ggplot(plotdata,aes(Incident.Year,count,fill=Incident.Year))+geom_bar(stat="identity")+theme_bw()+
        facet_wrap(~Pattern,nrow = 7)+geom_text(aes(Incident.Year,count,label=count),size=3)+theme(legend.position="bottom")+
        xlab("Year 2009- 2014")+ylab("# Breaches")+ggtitle(paste("Breach Pattern 2009-2014 for",selsector,"sector"))
      
    }
  }) 
  
  output$tablesector=renderDataTable({
    selsector=input$selsec
    
    if (selsector=="All"){
      breachdetails%>%
        select(-Source.Reference)
    } else {
        breachdetails%>%
        filter(Sector==selsector)%>%
        select(-Source.Reference)
      
      }
  },options = list(autoWidth = FALSE,
                    columnDefs = list(list(sWidth = "150px", sWidth = "30px",
                                        sWidth = "30px", sWidth = "30px"))))
  
  
  breachactor=reactive({
    selectsector=input$breanasec
    selectactor=input$breanaact
    
   
    
    if (selectactor=="All"){
        psactor=ps%>%
        filter(sector==selectsector)%>%
        select(1212:1214)%>%
        mutate_each(funs(as.numeric))
      meltactor=melt(psactor,variable.name = "Actor.types",value.name = "Total.Attacks")
      resultactor=meltactor%>%
        group_by(Actor.types)%>%
        summarise(Total.Attacks=sum(Total.Attacks))
      resultactor$TypePercent=round(resultactor$Total.Attacks/sum(resultactor$Total.Attacks)*100,1)
      
      ggplot(resultactor,aes(Actor.types,Total.Attacks,fill=Actor.types))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x="Actor Type",y="Number of companies Breached",title="Distribution of Attacks by Actors")+
        geom_text(aes(Actor.types,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)
      
      
    } else if (selectactor=="External Actor Country"){
      psactor=ps%>%
        filter(sector==selectsector)%>%
        select(248:498)%>%
        mutate_each(funs(as.numeric))
      
      meltactor=melt(psactor,variable.name = "Actor.Country",value.name = "Total.Attacks")
      resultactor=meltactor%>%
        group_by(Actor.Country)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultactor$Actor.Country=sub("actor.external.country.","",resultactor$Actor.Country)
      resultactor$Country=countrytable$fullname[match(resultactor$Actor.Country,countrytable$victim.country)]
      resultactor=resultactor[,c(3,1,2)]
      resultactor=resultactor[,-2]
      resultactor$TypePercent=round(resultactor$Total.Attacks/sum(resultactor$Total.Attacks)*100,1)
      unknown=sum(resultactor$Total.Attacks[resultactor$Country=="unknown"|resultactor$Country=="na"])
      resultactor=resultactor%>%
        filter(!(Country=="unknown"|Country=="na"))
      
      
      ggplot(resultactor,aes(Country,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x="Actor Country (removed all NA or unknown data points)",y="Number of successful breaches",title="Distribution of Attacks by Actor's Country")+
        geom_text(aes(Country,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="green", mid = "orange",high="red")+theme(legend.position="none")
        
      
      
    } else if (selectactor=="External Actor types"){
      psactor=ps%>%
        filter(sector==selectsector)%>%
        select(513:526)%>%
        mutate_each(funs(as.numeric))
      
      meltactor=melt(psactor,variable.name = "Actor.Type",value.name = "Total.Attacks")
      resultactor=meltactor%>%
        group_by(Actor.Type)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultactor$Actor.Type=sub("actor.external.variety.","",resultactor$Actor.Type)
      resultactor$TypePercent=round(resultactor$Total.Attacks/sum(resultactor$Total.Attacks)*100,1)
      unknown=sum(resultactor$Total.Attacks[resultactor$Actor.Type=="unknown"|resultactor$Actor.Type=="na"])
      resultactor=resultactor%>%
        filter(!(Actor.Type=="unknown"|Actor.Type=="na"))
      
      
      ggplot(resultactor,aes(Actor.Type,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Actor Types (removed",unknown,"unknown data points)"),y="Number of successful breaches",title="Distribution of Attacks by External Actor Types")+
        geom_text(aes(Actor.Type,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="green", mid = "orange",high="red")+theme(legend.position="none")
      
      
    }else if (selectactor=="Internal Actor types"){
      psactor=ps%>%
        filter(sector==selectsector)%>%
        select(551:565)%>%
        mutate_each(funs(as.numeric))
      
      meltactor=melt(psactor,variable.name = "Actor.Type",value.name = "Total.Attacks")
      resultactor=meltactor%>%
        group_by(Actor.Type)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultactor$Actor.Type=sub("actor.internal.variety.","",resultactor$Actor.Type)
      resultactor$TypePercent=round(resultactor$Total.Attacks/sum(resultactor$Total.Attacks)*100,1)
      unknown=sum(resultactor$Total.Attacks[resultactor$Actor.Type=="unknown"|resultactor$Actor.Type=="na"])
      resultactor=resultactor%>%
        filter(!(Actor.Type=="unknown"|Actor.Type=="na"))
      
      
      ggplot(resultactor,aes(Actor.Type,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Actor Types (removed",unknown,"unknown data points)"),y="Number of successful breaches",title="Distribution of Attacks by Internal Actor Types")+
        geom_text(aes(Actor.Type,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="green", mid = "orange",high="red")+theme(legend.position="none")
      
      
    } else if (selectactor=="External Actor Motives"){
      psactor=ps%>%
        filter(sector==selectsector)%>%
        select(499:509)%>%
        mutate_each(funs(as.numeric))
      
      meltactor=melt(psactor,variable.name = "Actor.Motives",value.name = "Total.Attacks")
      resultactor=meltactor%>%
        group_by(Actor.Motives)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultactor$Actor.Motives=sub("actor.external.motive.","",resultactor$Actor.Motives)
      resultactor$TypePercent=round(resultactor$Total.Attacks/sum(resultactor$Total.Attacks)*100,1)
      unknown=sum(resultactor$Total.Attacks[resultactor$Actor.Motives=="unknown"|resultactor$Actor.Motives=="na"])
      resultactor=resultactor%>%
        filter(!(Actor.Motives=="unknown"|Actor.Motives=="na"))
      
      
      ggplot(resultactor,aes(Actor.Motives,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Actor Motives (removed",unknown,"unknown data points)"),y="Number of successful breaches",title="Distribution of Attacks by External Actor Motives")+
        geom_text(aes(Actor.Motives,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="green", mid = "orange",high="red")+theme(legend.position="none")
      
      
    }else if (selectactor=="Internal Actor Motives"){
      psactor=ps%>%
        filter(sector==selectsector)%>%
        select(539:549)%>%
        mutate_each(funs(as.numeric))
      
      meltactor=melt(psactor,variable.name = "Actor.Motives",value.name = "Total.Attacks")
      resultactor=meltactor%>%
        group_by(Actor.Motives)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultactor$Actor.Motives=sub("actor.internal.motive.","",resultactor$Actor.Motives)
      resultactor$TypePercent=round(resultactor$Total.Attacks/sum(resultactor$Total.Attacks)*100,1)
      unknown=sum(resultactor$Total.Attacks[resultactor$Actor.Motives=="unknown"|resultactor$Actor.Motives=="na"])
      resultactor=resultactor%>%
        filter(!(Actor.Motives=="unknown"|Actor.Motives=="na"))
      
      
      ggplot(resultactor,aes(Actor.Motives,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Actor Motives (removed",unknown,"unknown data points)"),y="Number of successful breaches",title="Distribution of Attacks by Internal Actor Motives")+
        geom_text(aes(Actor.Motives,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="green", mid = "orange",high="red")+theme(legend.position="none")
      
      
    }else if (selectactor=="Partner Actor Motives"){
      psactor=ps%>%
        filter(sector==selectsector)%>%
        select(567:577)%>%
        mutate_each(funs(as.numeric))
      
      meltactor=melt(psactor,variable.name = "Actor.Motives",value.name = "Total.Attacks")
      resultactor=meltactor%>%
        group_by(Actor.Motives)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultactor$Actor.Motives=sub("actor.partner.motive.","",resultactor$Actor.Motives)
      resultactor$TypePercent=round(resultactor$Total.Attacks/sum(resultactor$Total.Attacks)*100,1)
      unknown=sum(resultactor$Total.Attacks[resultactor$Actor.Motives=="unknown"|resultactor$Actor.Motives=="na"])
      resultactor=resultactor%>%
        filter(!(Actor.Motives=="unknown"|Actor.Motives=="na"))
      
      
      ggplot(resultactor,aes(Actor.Motives,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Actor Motives (removed",unknown,"unknown data points)"),y="Number of successful breaches",title="Distribution of Attacks by Partner Actor Motives")+
        geom_text(aes(Actor.Motives,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="green", mid = "orange",high="red")+theme(legend.position="none")
      
     
    }
  })
  
  output$breanaintro=renderText({
    
    "In this section, we will analyze specifics of the breach including Actors, Actions (Attack Types), Assets Impacted and Impact"
  })
  
  output$breanaheading2=renderText({
    "Analysis by Actors and Motives"
  })
  
  output$breanaplot1=renderPlot({
    
    breachactor()
  
  })
  
  # Analysis by Attack types
  
  output$breanaheading3=renderText({
    "Analysis by Attack Varieties"
  })
  
  breachattack=reactive({
    selectsector=input$breanaattsec
    selectattack=input$breanaattopt
    
    if (selectattack=="All"){
      psattack=ps%>%
        filter(sector==selectsector)%>%
        select(1216:1222)%>%
        mutate_each(funs(as.numeric))
      meltattack=melt(psattack,variable.name = "Attack.types",value.name = "Total.Attacks")
      resultattack=meltattack%>%
        group_by(Attack.types)%>%
        summarise(Total.Attacks=sum(Total.Attacks))
      resultattack$TypePercent=round(resultattack$Total.Attacks/sum(resultattack$Total.Attacks)*100,1)
      
      ggplot(resultattack,aes(Attack.types,Total.Attacks,fill=Attack.types))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x="Attack Type",y="Number of companies Breached",title="Distribution of Attacks by Attack Types")+
        geom_text(aes(Attack.types,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)
      
      
    } else if (selectattack=="Hacking"){
      psattack=ps%>%
        filter(sector==selectsector)%>%
        select(54:100)%>%
        mutate_each(funs(as.numeric))
      
      meltattack=melt(psattack,variable.name = "Attack.Type",value.name = "Total.Attacks")
      resultattack=meltattack%>%
        group_by(Attack.Type)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultattack$Attack.Type=sub("action.hacking.variety.","",resultattack$Attack.Type)
      resultattack$TypePercent=round(resultattack$Total.Attacks/sum(resultattack$Total.Attacks)*100,1)
      unknown=sum(resultattack$Total.Attacks[resultattack$Attack.Type=="unknown"|resultattack$Attack.Type=="na"])
      resultattack=resultattack%>%
        filter(!(Attack.Type=="unknown"|Attack.Type=="na"))
      
      
      ggplot(resultattack,aes(Attack.Type,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Attack Types (removed",unknown,"unknown data points)"),y="Number of successful breaches",title=paste("Distribution of Attacks by",selectattack,"Attack Varieties"))+
        geom_text(aes(Attack.Type,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="yellow", mid = "orange",high="red")+theme(legend.position="none")
      
      
      
    } else if (selectattack=="Malware"){
      psattack=ps%>%
        filter(sector==selectsector)%>%
        select(114:140)%>%
        mutate_each(funs(as.numeric))
      
      meltattack=melt(psattack,variable.name = "Attack.Type",value.name = "Total.Attacks")
      resultattack=meltattack%>%
        group_by(Attack.Type)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultattack$Attack.Type=sub("action.malware.variety.","",resultattack$Attack.Type)
      resultattack$TypePercent=round(resultattack$Total.Attacks/sum(resultattack$Total.Attacks)*100,1)
      unknown=sum(resultattack$Total.Attacks[resultattack$Attack.Type=="unknown"|resultattack$Attack.Type=="na"])
      resultattack=resultattack%>%
        filter(!(Attack.Type=="unknown"|Attack.Type=="na"))
      
      
      ggplot(resultattack,aes(Attack.Type,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Attack Types (removed",unknown,"unknown data points)"),y="Number of successful breaches",title=paste("Distribution of Attacks by",selectattack,"Attack Varieties"))+
        geom_text(aes(Attack.Type,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="yellow", mid = "orange",high="red")+theme(legend.position="none")
      
      
    }else if (selectattack=="Social"){
      psattack=ps%>%
        filter(sector==selectsector)%>%
        select(222:234)%>%
        mutate_each(funs(as.numeric))
      
      meltattack=melt(psattack,variable.name = "Attack.Type",value.name = "Total.Attacks")
      resultattack=meltattack%>%
        group_by(Attack.Type)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultattack$Attack.Type=sub("action.social.variety.","",resultattack$Attack.Type)
      resultattack$TypePercent=round(resultattack$Total.Attacks/sum(resultattack$Total.Attacks)*100,1)
      unknown=sum(resultattack$Total.Attacks[resultattack$Attack.Type=="unknown"|resultattack$Attack.Type=="na"])
      resultattack=resultattack%>%
        filter(!(Attack.Type=="unknown"|Attack.Type=="na"))
      
      
      ggplot(resultattack,aes(Attack.Type,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Attack Types (removed",unknown,"unknown data points)"),y="Number of successful breaches",title=paste("Distribution of Attacks by",selectattack,"Attack Varieties"))+
        geom_text(aes(Attack.Type,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="yellow", mid = "orange",high="red")+theme(legend.position="none")
      
      
    } else if (selectattack=="Misuse"){
      psattack=ps%>%
        filter(sector==selectsector)%>%
        select(156:167)%>%
        mutate_each(funs(as.numeric))
      
      meltattack=melt(psattack,variable.name = "Attack.Type",value.name = "Total.Attacks")
      resultattack=meltattack%>%
        group_by(Attack.Type)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultattack$Attack.Type=sub("action.misuse.variety.","",resultattack$Attack.Type)
      resultattack$TypePercent=round(resultattack$Total.Attacks/sum(resultattack$Total.Attacks)*100,1)
      unknown=sum(resultattack$Total.Attacks[resultattack$Attack.Type=="unknown"|resultattack$Attack.Type=="na"])
      resultattack=resultattack%>%
        filter(!(Attack.Type=="unknown"|Attack.Type=="na"))
      
      
      ggplot(resultattack,aes(Attack.Type,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Attack Types (removed",unknown,"unknown data points)"),y="Number of successful breaches",title=paste("Distribution of Attacks by",selectattack,"Attack Varieties"))+
        geom_text(aes(Attack.Type,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="yellow", mid = "orange",high="red")+theme(legend.position="none")
      
      
    }else if (selectattack=="Error"){
      psattack=ps%>%
        filter(sector==selectsector)%>%
        select(28:44)%>%
        mutate_each(funs(as.numeric))
      
      meltattack=melt(psattack,variable.name = "Attack.Type",value.name = "Total.Attacks")
      resultattack=meltattack%>%
        group_by(Attack.Type)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultattack$Attack.Type=sub("action.error.variety.","",resultattack$Attack.Type)
      resultattack$TypePercent=round(resultattack$Total.Attacks/sum(resultattack$Total.Attacks)*100,1)
      unknown=sum(resultattack$Total.Attacks[resultattack$Attack.Type=="unknown"|resultattack$Attack.Type=="na"])
      resultattack=resultattack%>%
        filter(!(Attack.Type=="unknown"|Attack.Type=="na"))
      
      
      ggplot(resultattack,aes(Attack.Type,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Attack Types (removed",unknown,"unknown data points)"),y="Number of successful breaches",title=paste("Distribution of Attacks by",selectattack,"Attack Varieties"))+
        geom_text(aes(Attack.Type,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="yellow", mid = "orange",high="red")+theme(legend.position="none")
      
      
    }else if (selectattack=="Environmental"){
      psattack=ps%>%
        filter(sector==selectsector)%>%
        select(2:26)%>%
        mutate_each(funs(as.numeric))
      
      meltattack=melt(psattack,variable.name = "Attack.Type",value.name = "Total.Attacks")
      resultattack=meltattack%>%
        group_by(Attack.Type)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultattack$Attack.Type=sub("action.environmental.variety.","",resultattack$Attack.Type)
      resultattack$TypePercent=round(resultattack$Total.Attacks/sum(resultattack$Total.Attacks)*100,1)
      unknown=sum(resultattack$Total.Attacks[resultattack$Attack.Type=="unknown"|resultattack$Attack.Type=="na"])
      resultattack=resultattack%>%
        filter(!(Attack.Type=="unknown"|Attack.Type=="na"))
      
      
      ggplot(resultattack,aes(Attack.Type,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Attack Types (removed",unknown,"unknown data points)"),y="Number of successful breaches",title=paste("Distribution of Attacks by",selectattack,"Attack Varieties"))+
        geom_text(aes(Attack.Type,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="yellow", mid = "orange",high="red")+theme(legend.position="none")
      
      
    }
  })
  
  output$breanaplot2=renderPlot({
    
    breachattack()
    
  })
  
 ## Analysis by Assets and Attributes
  
  
  
  output$breanaheading4=renderText({
    "Analysis by Assets Impacted, Attributes - Confidentiality, Availability, Integrity and Discovery Methods"
  })
  
  breachasset=reactive({
    #browser()
    selectsector=input$breanaastsec
    selectattack=input$breanaastopt
    
    if (selectattack=="All Assets"){
      psattack=ps%>%
        filter(sector==selectsector)%>%
        select(1224:1230)%>%
        mutate_each(funs(as.numeric))
      meltattack=melt(psattack,variable.name = "Asset.types",value.name = "Total.Attacks")
      resultattack=meltattack%>%
        group_by(Asset.types)%>%
        summarise(Total.Attacks=sum(Total.Attacks))
      resultattack$Asset.types=sub("asset.variety.","",resultattack$Asset.types)
      resultattack$TypePercent=round(resultattack$Total.Attacks/sum(resultattack$Total.Attacks)*100,1)
      unknown=sum(resultattack$Total.Attacks[resultattack$Asset.types=="unknown"|resultattack$Asset.types=="na"])
      resultattack=resultattack%>%
        filter(!(Asset.types=="unknown"|Asset.types=="na"))
      
      ggplot(resultattack,aes(Asset.types,Total.Attacks,fill=Asset.types))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x="Asset Type",y="Number of companies Breached",title="Distribution of Attacks by Asset Impacted")+
        geom_text(aes(Asset.types,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)
      
    } else if (selectattack=="Asset Varieties"){
      psattack=ps%>%
        filter(sector==selectsector)%>%
        select(663:744)%>%
        mutate_each(funs(as.numeric))
      
      meltattack=melt(psattack,variable.name = "Asset.Type",value.name = "Total.Attacks")
      resultattack=meltattack%>%
        group_by(Asset.Type)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultattack$Asset.Type=sub("asset.assets.variety.","",resultattack$Asset.Type)
      resultattack$TypePercent=round(resultattack$Total.Attacks/sum(resultattack$Total.Attacks)*100,1)
      unknown=sum(resultattack$Total.Attacks[resultattack$Asset.Type=="unknown"|resultattack$Asset.Type=="na"])
      resultattack=resultattack%>%
        filter(!(Asset.Type=="unknown"|Asset.Type=="na"))
      
      
      ggplot(resultattack,aes(Asset.Type,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Asset Types (removed",unknown,"unknown data points)"),y="Number of successful breaches",title=paste("Distribution of Attacks by",selectattack,"Asset Types"))+
        geom_text(aes(Asset.Type,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="yellow", mid = "orange",high="red")+theme(legend.position="none")+
        geom_text(aes(5,100,label="s- Server \n n- Network \n u- User Developer \n m- Media \n p- Person \n t- Terminal"),size=3)
      
      
      
    } else if (selectattack=="Attribute Availability Loss"){
      psattack=ps%>%
        filter(sector==selectsector)%>%
        select(766:773)%>%
        mutate_each(funs(as.numeric))
      
      meltattack=melt(psattack,variable.name = "Availability.Type",value.name = "Total.Attacks")
      resultattack=meltattack%>%
        group_by(Availability.Type)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultattack$Availability.Type=sub("attribute.availability.variety.","",resultattack$Availability.Type)
      resultattack$TypePercent=round(resultattack$Total.Attacks/sum(resultattack$Total.Attacks)*100,1)
      unknown=sum(resultattack$Total.Attacks[resultattack$Availability.Type=="unknown"|resultattack$Availability.Type=="na"])
      resultattack=resultattack%>%
        filter(!(Availability.Type=="unknown"|Availability.Type=="na"))
      
      
      ggplot(resultattack,aes(Availability.Type,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Availability Loss Types (removed",unknown,"unknown data points)"),y="Number of successful breaches",title=paste("Distribution of Attacks by",selectattack,"varieties"))+
        geom_text(aes(Availability.Type,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="yellow", mid = "orange",high="red")+theme(legend.position="none")
      
      
    }else if (selectattack=="Attribute Confidentiality Data Loss"){
      psattack=ps%>%
        filter(sector==selectsector)%>%
        select(795:809)%>%
        mutate_each(funs(as.numeric))
      
      meltattack=melt(psattack,variable.name = "Confidentiality.Type",value.name = "Total.Attacks")
      resultattack=meltattack%>%
        group_by(Confidentiality.Type)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultattack$Confidentiality.Type=sub("attribute.confidentiality.data.variety.","",resultattack$Confidentiality.Type)
      resultattack$TypePercent=round(resultattack$Total.Attacks/sum(resultattack$Total.Attacks)*100,1)
      unknown=sum(resultattack$Total.Attacks[resultattack$Confidentiality.Type=="unknown"|resultattack$Confidentiality.Type=="na"])
      resultattack=resultattack%>%
        filter(!(Confidentiality.Type=="unknown"|Confidentiality.Type=="na"))
      
      
      ggplot(resultattack,aes(Confidentiality.Type,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Confidentiality Data Loss Types (removed",unknown,"unknown data points)"),y="Number of successful breaches",title=paste("Distribution of Attacks by",selectattack,"Varieties"))+
        geom_text(aes(Confidentiality.Type,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="yellow", mid = "orange",high="red")+theme(legend.position="none")
      
      
    } else if (selectattack=="Attribute Integrity Loss"){
      psattack=ps%>%
        filter(sector==selectsector)%>%
        select(820:833)%>%
        mutate_each(funs(as.numeric))
      
      meltattack=melt(psattack,variable.name = "Integrity.Type",value.name = "Total.Attacks")
      resultattack=meltattack%>%
        group_by(Integrity.Type)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultattack$Integrity.Type=sub("attribute.integrity.variety.","",resultattack$Integrity.Type)
      resultattack$TypePercent=round(resultattack$Total.Attacks/sum(resultattack$Total.Attacks)*100,1)
      unknown=sum(resultattack$Total.Attacks[resultattack$Integrity.Type=="unknown"|resultattack$Integrity.Type=="na"])
      resultattack=resultattack%>%
        filter(!(Integrity.Type=="unknown"|Integrity.Type=="na"))
      
      
      ggplot(resultattack,aes(Integrity.Type,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Integrity Loss Types (removed",unknown,"unknown data points)"),y="Number of successful breaches",title=paste("Distribution of Attacks by",selectattack,"Varieties"))+
        geom_text(aes(Integrity.Type,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="yellow", mid = "orange",high="red")+theme(legend.position="none")
      
      
    }else if (selectattack=="Discovery Methods External"){
      psattack=ps%>%
        filter(sector==selectsector)%>%
        select(845:855)%>%
        mutate_each(funs(as.numeric))
      
      meltattack=melt(psattack,variable.name = "DiscoveryExt.Type",value.name = "Total.Attacks")
      resultattack=meltattack%>%
        group_by(DiscoveryExt.Type)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultattack$DiscoveryExt.Type=sub("discovery_method.ext...","",resultattack$DiscoveryExt.Type)
      resultattack$TypePercent=round(resultattack$Total.Attacks/sum(resultattack$Total.Attacks)*100,1)
      unknown=sum(resultattack$Total.Attacks[resultattack$DiscoveryExt.Type=="unknown"|resultattack$DiscoveryExt.Type=="na"])
      resultattack=resultattack%>%
        filter(!(DiscoveryExt.Type=="unknown"|DiscoveryExt.Type=="na"))
      
      
      ggplot(resultattack,aes(DiscoveryExt.Type,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Discovery Methods External Types (removed",unknown,"unknown data points)"),y="Number of successful breaches",title=paste("Distribution of Attacks by",selectattack,"Varieties"))+
        geom_text(aes(DiscoveryExt.Type,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="yellow", mid = "orange",high="red")+theme(legend.position="none")
      
      
    }else if (selectattack=="Discovery Methods Internal"){
      psattack=ps%>%
        filter(sector==selectsector)%>%
        select(856:868)%>%
        mutate_each(funs(as.numeric))
      
      meltattack=melt(psattack,variable.name = "DiscoveryInt.Type",value.name = "Total.Attacks")
      resultattack=meltattack%>%
        group_by(DiscoveryInt.Type)%>%
        summarise(Total.Attacks=sum(Total.Attacks))%>%
        filter(!Total.Attacks==0)
      resultattack$DiscoveryInt.Type=sub("discovery_method.int...","",resultattack$DiscoveryInt.Type)
      resultattack$TypePercent=round(resultattack$Total.Attacks/sum(resultattack$Total.Attacks)*100,1)
      unknown=sum(resultattack$Total.Attacks[resultattack$DiscoveryInt.Type=="unknown"|resultattack$DiscoveryInt.Type=="na"])
      resultattack=resultattack%>%
        filter(!(DiscoveryInt.Type=="unknown"|DiscoveryInt.Type=="na"))
      
      
      ggplot(resultattack,aes(DiscoveryInt.Type,Total.Attacks,fill=Total.Attacks))+ geom_bar(stat="identity")+theme_bw()+coord_flip()+
        labs(x=paste("Discovery Methods Internal Types (removed",unknown,"unknown data points)"),y="Number of successful breaches",title=paste("Distribution of Attacks by",selectattack,"Varieties"))+
        geom_text(aes(DiscoveryInt.Type,Total.Attacks,label=paste0(Total.Attacks,", ",TypePercent,"%")),size=4)+scale_fill_gradient2(low="yellow", mid = "orange",high="red")+theme(legend.position="none")
      
    }
    
    })
  
  output$breanaplot3=renderPlot({
    breachasset()
    
  })
  }
  
 
shinyApp(ui,server)